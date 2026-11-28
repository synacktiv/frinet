"""Timeline docked on the right edge of IDA, colored by the module the PC runs in"""

import itertools
from dataclasses import dataclass
from typing import Callable

from frinet import MODULE_MARKER_MIXED, MODULE_MARKER_NONE

from . import theme
from .qt import mouse_position, wheel_position
from .qt.QtCore import QEvent, QPoint, QPointF, QRectF, Qt
from .qt.QtGui import (
    QBrush,
    QColor,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPalette,
    QPen,
    QPolygon,
    QWheelEvent,
)
from .qt.QtWidgets import QGridLayout, QSizePolicy, QToolBar, QToolTip, QWidget
from .session import Session
from .utils import notify_calltree_needed
from .widget import FrinetWidget

ZOOM_FACTOR = 1.25
VIEW_BAR_WIDTH = 64
VIEW_BAR_WIDTH_MIN = 24
VIEW_BAR_WIDTH_MAX = 480
TRACE_BAR_WIDTH = 20
HANDLE_WIDTH = 5
THICK_LINE = 2
ARROW_MARGIN = 12
ARROW_WIDTH = 9
ARROW_HALF_HEIGHT = 6
OUT_OF_VIEW_FADING = 170
RULER_WIDTH = 16
TICK_SPACING_MIN = 12
TICK_LENGTH = 7
RULER_GAP = 10
STEP_HEIGHT_MIN = 8
FOLLOW_BUTTON_HEIGHT = 22
FOLLOW_BUTTON_GAP = 4
CROSSHAIR_RADIUS = 5
CROSSHAIR_ARM = 4


def screen_painter(widget: QWidget) -> QPainter:
    """In pixels of the screen: scaled by 1.5, a pixel of the widget is one or
    two pixels of the screen"""
    painter = QPainter(widget)
    scale = 1 / widget.devicePixelRatioF()
    painter.scale(scale, scale)
    return painter


def screen_pixels(widget: QWidget, length: float) -> int:
    return round(length * widget.devicePixelRatioF())


def paint_frame(
    painter: QPainter,
    x: int,
    y: int,
    width: int,
    height: int,
    thickness: int,
    color: QColor,
) -> None:
    painter.fillRect(x, y, width, thickness, color)
    painter.fillRect(x, y + height - thickness, width, thickness, color)
    painter.fillRect(x, y, thickness, height, color)
    painter.fillRect(x + width - thickness, y, thickness, height, color)


@dataclass(frozen=True)
class TimeRange:
    """The times `min..=max`, cut in slices like `Trace.timeline_pixels`"""

    min: int
    max: int

    @property
    def steps(self) -> int:
        return self.max - self.min + 1

    def slice_start(self, pixels: int, pixel: int) -> int:
        return self.min + pixel * self.steps // pixels

    def slice_at(self, pixels: int, pixel: int) -> "TimeRange":
        start = self.slice_start(pixels, pixel)
        return TimeRange(start, max(start, self.slice_start(pixels, pixel + 1) - 1))

    def pixels_of(self, pixels: int, time: int) -> range:
        offset = time - self.min
        last = ((offset + 1) * pixels + self.steps - 1) // self.steps - 1
        first = min(last, (offset * pixels + self.steps - 1) // self.steps)
        return range(first, last + 1)

    def zoomed(self, anchor: int, fraction: float, steps: int) -> "TimeRange":
        """`steps` times around `anchor`, which stays at `fraction` of the range"""
        start = anchor - round(fraction * steps)
        start = max(self.min, min(self.max - steps + 1, start))
        return TimeRange(start, start + steps - 1)


class TimelineBar(QWidget):
    timeline: "TimelineWidget"
    zoomable: bool

    def __init__(self, timeline: "TimelineWidget", zoomable: bool) -> None:
        super().__init__()
        self.timeline = timeline
        self.zoomable = zoomable

        self.setFixedWidth(VIEW_BAR_WIDTH if zoomable else TRACE_BAR_WIDTH)
        self.setMinimumHeight(32)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMouseTracking(zoomable)

    @property
    def session(self) -> Session:
        return self.timeline.session

    def time_range(self) -> TimeRange:
        return self.timeline.view if self.zoomable else self.timeline.whole_trace

    def _pixels(self) -> int:
        return screen_pixels(self, self.height())

    def _pixel_at(self, y: float) -> int:
        return max(0, min(self._pixels() - 1, int(y * self.devicePixelRatioF())))

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() != Qt.MouseButton.LeftButton:
            return
        pixel = self._pixel_at(mouse_position(event).y())
        self.timeline.goto_clicked(self.time_range().slice_start(self._pixels(), pixel))

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if self.zoomable and event.button() == Qt.MouseButton.LeftButton:
            self.timeline.reset_zoom()

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if not self.zoomable:
            return
        y = mouse_position(event).y()
        time_slice = self.time_range().slice_at(self._pixels(), self._pixel_at(y))
        [module] = self.session.trace.timeline_pixels(time_slice.min, time_slice.max, 1)

        if module == MODULE_MARKER_MIXED:
            modules = self.session.trace.timeline_distinct_modules_in_range(
                time_slice.min, time_slice.max
            )
        else:
            modules = [module]
        text = "\n".join(self.timeline.module_name(module) for module in modules)
        QToolTip.showText(self.mapToGlobal(QPoint(self.width(), int(y))), text, self)

    def leaveEvent(self, event: QEvent) -> None:
        QToolTip.hideText()

    def wheelEvent(self, event: QWheelEvent) -> None:
        # some platforms turn the vertical wheel horizontal with shift
        delta = event.angleDelta().y() or event.angleDelta().x()
        if delta == 0:
            return
        forward = delta < 0
        modifiers = event.modifiers()

        if modifiers & Qt.KeyboardModifier.ShiftModifier:
            if self.zoomable:
                pixel = self._pixel_at(wheel_position(event).y())
                self.timeline.zoom(pixel, self._pixels(), zoom_in=forward)
            return

        if not modifiers & Qt.KeyboardModifier.ControlModifier:
            self.session.goto(self.session.time + (1 if forward else -1))
            return

        tree = self.session.calltree
        if tree is None:
            # stepping over a call needs the calltree
            notify_calltree_needed()
            return

        time = self.session.time
        self.session.goto(
            tree.step_over(time) if forward else tree.step_back_over(time)
        )

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = screen_painter(self)
        palette = self.palette()
        text = palette.color(QPalette.ColorRole.Text)
        background = theme.panel(palette.color(QPalette.ColorRole.Base), text)
        accents = theme.accents()
        width, height = screen_pixels(self, self.width()), self._pixels()
        time_range = self.time_range()

        painter.fillRect(0, 0, width, height, background)

        modules = self.session.trace.timeline_pixels(
            time_range.min, time_range.max, height
        )
        no_module = QBrush(theme.muted(background, text), Qt.BrushStyle.BDiagPattern)
        rows = itertools.groupby(enumerate(modules), key=lambda row: row[1])
        for module, run in rows:
            run = list(run)
            painter.fillRect(
                0, run[0][0], width, len(run), self._brush(module, accents, no_module)
            )

        if height >= screen_pixels(self, STEP_HEIGHT_MIN) * time_range.steps:
            for step in range(time_range.min + 1, time_range.max + 1):
                y = time_range.pixels_of(height, step).start
                painter.fillRect(0, y, width, 1, background)

        if not self.zoomable and self.timeline.view != time_range:
            self._paint_view(painter, time_range, width, height, background, text)

        time = self.session.time
        if time_range.min <= time <= time_range.max:
            pixels = time_range.pixels_of(height, time)
            self._paint_current_time(painter, pixels, width, accents.current_time)

    def _paint_current_time(
        self, painter: QPainter, pixels: range, width: int, color: QColor
    ) -> None:
        thickness = screen_pixels(self, THICK_LINE)
        if len(pixels) < 3 * thickness:
            painter.fillRect(0, pixels.start, width, thickness, color)
        else:
            paint_frame(painter, 0, pixels.start, width, len(pixels), thickness, color)

    def _brush(self, module: int, accents: theme.Accents, no_module: QBrush) -> QBrush:
        if module == MODULE_MARKER_NONE:
            return no_module
        if module == MODULE_MARKER_MIXED:
            return QBrush(accents.mixed_modules)
        if module == self.timeline.idb_module:
            return QBrush(accents.idb_module)
        return QBrush(accents.modules[module % len(accents.modules)])

    def _paint_view(
        self,
        painter: QPainter,
        time_range: TimeRange,
        width: int,
        height: int,
        background: QColor,
        text: QColor,
    ) -> None:
        view = self.timeline.view
        top = time_range.pixels_of(height, view.min).start
        bottom = time_range.pixels_of(height, view.max).stop

        fading = QColor(background)
        fading.setAlpha(OUT_OF_VIEW_FADING)
        painter.fillRect(0, 0, width, top, fading)
        painter.fillRect(0, bottom, width, height - bottom, fading)

        thickness = screen_pixels(self, THICK_LINE)
        frame_height = max(2 * thickness, bottom - top)
        paint_frame(painter, 0, top, width, frame_height, thickness, text)


class TimelineRuler(QWidget):
    timeline: "TimelineWidget"

    def __init__(self, timeline: "TimelineWidget") -> None:
        super().__init__()
        self.timeline = timeline
        self.setFixedWidth(RULER_WIDTH)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = screen_painter(self)
        color = self.palette().color(QPalette.ColorRole.Text)
        view = self.timeline.view
        width = screen_pixels(self, self.width())
        height = screen_pixels(self, self.height())
        minor_length = screen_pixels(self, TICK_LENGTH)
        major_thickness = screen_pixels(self, THICK_LINE)

        step = 1
        while step * height < screen_pixels(self, TICK_SPACING_MIN) * view.steps:
            step *= 10

        first = -(-view.min // step) * step
        for time in range(first, view.max + 1, step):
            y = view.pixels_of(height, time).start
            if time % (step * 10) == 0:
                painter.fillRect(0, y, width, major_thickness, color)
            else:
                painter.fillRect(0, y, minor_length, 1, color)


class CurrentTimeArrow(QWidget):
    timeline: "TimelineWidget"

    def __init__(self, timeline: "TimelineWidget") -> None:
        super().__init__()
        self.timeline = timeline
        self.setFixedWidth(ARROW_MARGIN)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)

    def paintEvent(self, event: QPaintEvent) -> None:
        view = self.timeline.view
        time = self.timeline.session.time
        if not view.min <= time <= view.max:
            return

        pixels = view.pixels_of(screen_pixels(self, self.height()), time)
        y = (pixels.start + pixels.stop - 1) // 2
        right = screen_pixels(self, self.width()) - 1
        left = right - screen_pixels(self, ARROW_WIDTH)
        half_height = screen_pixels(self, ARROW_HALF_HEIGHT)

        painter = screen_painter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(theme.accents().current_time)
        painter.drawPolygon(
            QPolygon(
                [
                    QPoint(left, y - half_height),
                    QPoint(right, y),
                    QPoint(left, y + half_height),
                ]
            )
        )


@dataclass(frozen=True)
class HandleDrag:
    global_x: int
    view_bar_width: int


class ResizeHandle(QWidget):
    timeline: "TimelineWidget"
    drag_start: HandleDrag | None

    def __init__(self, timeline: "TimelineWidget") -> None:
        super().__init__()
        self.timeline = timeline
        self.drag_start = None
        self.setFixedWidth(HANDLE_WIDTH)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        self.setCursor(Qt.CursorShape.SizeHorCursor)

    def _global_x(self, event: QMouseEvent) -> int:
        return self.mapToGlobal(mouse_position(event).toPoint()).x()

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.drag_start = HandleDrag(
                self._global_x(event), self.timeline.view_bar.width()
            )

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        start = self.drag_start
        if start is None:
            return
        width = start.view_bar_width + start.global_x - self._global_x(event)
        width = max(VIEW_BAR_WIDTH_MIN, min(VIEW_BAR_WIDTH_MAX, width))
        self.timeline.view_bar.setFixedWidth(width)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self.drag_start = None

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = screen_painter(self)
        palette = self.palette()
        background = palette.color(QPalette.ColorRole.Window)
        text = palette.color(QPalette.ColorRole.Text)
        height = screen_pixels(self, self.height())
        painter.fillRect(0, 0, 1, height, theme.blend(background, text, 0.7))


class FollowButton(QWidget):
    timeline: "TimelineWidget"

    def __init__(self, timeline: "TimelineWidget") -> None:
        super().__init__()
        self.timeline = timeline
        self.setFixedHeight(FOLLOW_BUTTON_HEIGHT)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("Follow the current time, in the middle of the view")

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.timeline.set_following(not self.timeline.following)

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        palette = self.palette()
        window = palette.color(QPalette.ColorRole.Window)
        text = palette.color(QPalette.ColorRole.Text)

        if self.timeline.following:
            highlight = palette.color(QPalette.ColorRole.Highlight)
            border, fill = highlight, QBrush(highlight)
            icon = palette.color(QPalette.ColorRole.HighlightedText)
        else:
            border, fill = theme.muted(window, text), QBrush(Qt.BrushStyle.NoBrush)
            icon = text

        box = QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5)
        painter.setPen(QPen(border, 1))
        painter.setBrush(fill)
        painter.drawRoundedRect(box, 3, 3)

        center = box.center()
        painter.setPen(QPen(icon, 1.5))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawEllipse(center, CROSSHAIR_RADIUS, CROSSHAIR_RADIUS)
        inner, outer = CROSSHAIR_RADIUS - 2, CROSSHAIR_RADIUS + CROSSHAIR_ARM
        for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            painter.drawLine(
                center + QPointF(dx * inner, dy * inner),
                center + QPointF(dx * outer, dy * outer),
            )


class TimelineWidget(FrinetWidget):
    """
    The wheel steps through the times, over the calls with ctrl, and zooms the
    view around the mouse with shift. A click goes to a time without moving
    the view, a double click on the view shows the whole trace again.
    """

    whole_trace: TimeRange
    view: TimeRange
    following: bool
    # while going to a time clicked on a bar, the view staying in place
    clicking: bool
    idb_module: int | None
    follow_button: FollowButton
    arrow: CurrentTimeArrow
    view_bar: TimelineBar
    ruler: TimelineRuler
    trace_bar: TimelineBar

    def __init__(
        self, session: Session, memory_view_ids: Callable[[], list[int]]
    ) -> None:
        super().__init__(session, memory_view_ids)
        trace = session.trace
        self.whole_trace = TimeRange(trace.times[0], trace.times[-1])
        self.view = self.whole_trace
        self.following = True
        self.clicking = False
        self.idb_module = (
            None if session.module is None else trace.modules.index(session.module)
        )
        self.setup_user_interface()

    def setup_user_interface(self) -> None:
        # the button above the zoomed view only, the bars of the same height
        layout = QGridLayout(self)
        layout.setContentsMargins(0, 3, 3, 3)
        layout.setHorizontalSpacing(0)
        layout.setVerticalSpacing(FOLLOW_BUTTON_GAP)

        self.setContextMenuPolicy(Qt.ContextMenuPolicy.PreventContextMenu)

        self.follow_button = FollowButton(self)
        self.arrow = CurrentTimeArrow(self)
        self.view_bar = TimelineBar(self, zoomable=True)
        self.ruler = TimelineRuler(self)
        self.trace_bar = TimelineBar(self, zoomable=False)
        layout.addWidget(ResizeHandle(self), 0, 0, 2, 1)
        layout.addWidget(self.follow_button, 0, 2)
        layout.addWidget(self.arrow, 1, 1)
        layout.addWidget(self.view_bar, 1, 2)
        layout.addWidget(self.ruler, 1, 3)
        layout.setColumnMinimumWidth(4, RULER_GAP)
        layout.addWidget(self.trace_bar, 1, 5)

    def module_name(self, module: int) -> str:
        if module == MODULE_MARKER_NONE:
            return "no module"
        return self.session.trace.modules[module].name

    def zoom(self, pixel: int, pixels: int, zoom_in: bool) -> None:
        view = self.view
        if zoom_in:
            steps = min(view.steps - 1, round(view.steps / ZOOM_FACTOR))
        else:
            steps = max(view.steps + 1, round(view.steps * ZOOM_FACTOR))
        steps = max(1, min(self.whole_trace.steps, steps))
        anchor = view.slice_start(pixels, pixel)
        self.view = self.whole_trace.zoomed(anchor, pixel / pixels, steps)
        self.update_bars()

    def reset_zoom(self) -> None:
        self.view = self.whole_trace
        self.update_bars()

    def set_following(self, following: bool) -> None:
        self.following = following
        self.follow_button.update()
        if following:
            self.center_view()

    def center_view(self) -> None:
        self.view = self.whole_trace.zoomed(self.session.time, 0.5, self.view.steps)
        self.update_bars()

    def goto_clicked(self, time: int) -> None:
        self.clicking = True
        try:
            self.session.goto(time)
        finally:
            self.clicking = False

    def update_bars(self) -> None:
        self.arrow.update()
        self.view_bar.update()
        self.ruler.update()
        self.trace_bar.update()

    def on_time_update(self) -> None:
        if self.following and not self.clicking:
            self.center_view()
        else:
            self.update_bars()


class TimelineDock(QToolBar):
    widget: TimelineWidget

    def __init__(self, widget: TimelineWidget) -> None:
        super().__init__()
        self.widget = widget
        self.setMovable(False)
        self.setContentsMargins(0, 0, 0, 0)
        self.addWidget(self.widget)
