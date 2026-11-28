"""
The trace window: the trace open, the time of the session, and the memory the
instruction at this time reads and writes.

From the trace to the screen:
- `read_memory_events` asks the trace what memory the instruction accesses,
- `BACKWARD_STEPS` and `FORWARD_STEPS` are the buttons around the time,
  `step_back_out` the one step the call tree has no query for,
- `ProgressBar` draws where the time is in the trace,
- `TraceWidget` builds them and gives them the time.
"""

import functools
import os
from dataclasses import dataclass
from typing import Callable

import ida_kernwin
from frinet import Calltree, MemoryAccess

from . import glyph_icons, theme
from .glyph_icons import Glyph, GlyphButtons
from .program_info import ensure_calltree
from .qt.QtCore import QPoint, QSize, Qt
from .qt.QtGui import QPainter, QPalette
from .qt.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QSizePolicy,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from .session import Session
from .utils import format_address, format_bytes
from .widget import MAX_ADDR, FrinetWidget, monospace_font, polished_metrics

# the memory the instruction at this time accesses


def read_memory_events(session: Session) -> list[MemoryAccess]:
    mem = session.mem
    return [*mem.reads(0, MAX_ADDR), *mem.writes(0, MAX_ADDR)]


def size_text(size: int) -> str:
    return "1 byte" if size == 1 else f"{size} bytes"


# the steps around the time


def step_back_out(tree: Calltree, time: int) -> int:
    """Time of the call of the span holding at `time`"""
    index = tree.span_at(time)
    return time - 1 if index is None else tree.span(index).time_range[0] - 1


def goto_in_calltree(move: Callable[[Calltree, int], int], session: Session) -> None:
    tree = ensure_calltree(session)
    if tree is not None:
        session.goto(move(tree, session.time))


@dataclass(frozen=True)
class Step:
    glyph: Glyph
    tooltip: str
    go: Callable[[Session], object]


BACKWARD_STEPS = [
    Step(
        glyph_icons.STEP_BACK_OUT,
        "Step out backward",
        functools.partial(goto_in_calltree, step_back_out),
    ),
    Step(
        glyph_icons.STEP_BACK_OVER,
        "Step over backward",
        functools.partial(
            goto_in_calltree, lambda tree, time: tree.step_back_over(time)
        ),
    ),
    Step(
        glyph_icons.STEP_BACK_INTO,
        "Step into backward",
        lambda session: session.step(-1),
    ),
]

FORWARD_STEPS = [
    Step(glyph_icons.STEP_INTO, "Step into", lambda session: session.step(1)),
    Step(
        glyph_icons.STEP_OVER,
        "Step over",
        functools.partial(goto_in_calltree, lambda tree, time: tree.step_over(time)),
    ),
    Step(
        glyph_icons.STEP_OUT,
        "Step out",
        functools.partial(goto_in_calltree, lambda tree, time: tree.step_out(time)),
    ),
]


# the widgets


class ProgressBar(QWidget):
    """Where the time is in the trace"""

    HEIGHT = 3

    def __init__(self):
        super().__init__()
        self.fraction = 0.0
        self.setFixedHeight(self.HEIGHT)

    def set_fraction(self, fraction: float) -> None:
        self.fraction = fraction
        self.update()

    def paintEvent(self, event) -> None:
        palette = self.palette()
        background = palette.color(QPalette.ColorRole.Window)
        text = palette.color(QPalette.ColorRole.WindowText)
        painter = QPainter(self)
        painter.fillRect(self.rect(), theme.blend(background, text, 0.15))
        width = round(self.width() * self.fraction)
        painter.fillRect(0, 0, width, self.height(), theme.accents().current_time)


class ElidedLabel(QLabel):
    """Ends its text with … when the label is too narrow for it"""

    def __init__(self, text: str):
        super().__init__(text)
        self.full_text = text
        # the layout gives it what is left, not the width of its text
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        metrics = self.fontMetrics()
        elide = Qt.TextElideMode.ElideRight
        self.setText(metrics.elidedText(self.full_text, elide, self.width()))


class TraceWidget(FrinetWidget):
    def __init__(self, session: Session, memory_view_ids: Callable[[], list[int]]):
        super().__init__(session, memory_view_ids)
        self.events: list[MemoryAccess] = []
        self.mono_font = monospace_font()
        self.setup_ui()
        self._update_label_colors()
        self.on_time_update()

    # construction

    def setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 4, 6, 0)
        layout.setSpacing(4)
        layout.addLayout(self._trace_line())
        layout.addLayout(self._time_line())
        self.progress = ProgressBar()
        layout.addWidget(self.progress)
        layout.addSpacing(6)
        layout.addLayout(self._events_title())
        self.event_list = self._event_list()
        layout.addWidget(self.event_list)

    def _trace_line(self) -> QHBoxLayout:
        trace = self.session.trace
        name = ElidedLabel(os.path.basename(trace.path))
        name.setToolTip(trace.path)
        # muted by `_update_label_colors`
        self.modules = QLabel(f"{len(trace.modules)} modules")

        line = QHBoxLayout()
        line.setSpacing(12)
        line.addWidget(name, 1)
        line.addWidget(self.modules)
        return line

    def _time_line(self) -> QHBoxLayout:
        self.time_edit = QLineEdit()
        self.time_edit.setFont(self.mono_font)
        self.time_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.time_edit.setMaximumWidth(120)
        self.time_edit.setMinimumWidth(
            polished_metrics(self.mono_font).horizontalAdvance(" 000000000 ")
        )
        self.time_edit.returnPressed.connect(self.on_time_edit)

        steps = [*BACKWARD_STEPS, *FORWARD_STEPS]
        glyphs = GlyphButtons(
            [step.glyph for step in steps], self.mono_font, glyph_icons.LARGE
        )
        buttons = []
        for step in steps:
            button = glyphs.button(step.glyph, step.tooltip)
            button.clicked.connect(functools.partial(self.on_step, step))
            buttons.append(button)

        line = QHBoxLayout()
        line.setSpacing(2)
        line.addStretch(1)
        for button in buttons[: len(BACKWARD_STEPS)]:
            line.addWidget(button)
        line.addSpacing(4)
        line.addWidget(self.time_edit)
        line.addSpacing(4)
        for button in buttons[len(BACKWARD_STEPS) :]:
            line.addWidget(button)
        line.addStretch(1)
        return line

    def _events_title(self) -> QHBoxLayout:
        # colored by `_update_label_colors`
        self.events_title = QLabel("Memory events")
        self.events_count = QLabel()
        line = QHBoxLayout()
        line.setSpacing(6)
        line.addWidget(self.events_title)
        line.addWidget(self.events_count)
        line.addStretch(1)
        return line

    def _event_list(self) -> QTreeWidget:
        view = QTreeWidget()
        # the kind, the address and the size
        view.setColumnCount(3)
        view.setHeaderHidden(True)
        view.setRootIsDecorated(False)
        view.setUniformRowHeights(True)
        # the rows keep the colors of their kind
        view.setSelectionMode(QTreeWidget.SelectionMode.NoSelection)
        view.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        # the background of the window: a list to read, not a field to edit
        view.setStyleSheet("QTreeWidget { background: transparent; border: none; }")
        view.setFont(self.mono_font)
        # room for one event, most instructions do one at most, the others scroll
        view.setMinimumHeight(self._row_height())
        view.itemClicked.connect(self.on_event_clicked)
        view.itemDoubleClicked.connect(self.on_event_double_clicked)
        view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        view.customContextMenuRequested.connect(self.show_context_menu)
        return view

    def _row_height(self) -> int:
        return polished_metrics(self.mono_font).height()

    def sizeHint(self) -> QSize:
        """A row of events and a half: the half shows when there are more"""
        hint = super().sizeHint()
        rows = round(1.5 * self._row_height())
        height = hint.height() - self.event_list.sizeHint().height() + rows
        return QSize(hint.width(), height)

    # time

    def on_time_update(self) -> None:
        session = self.session
        times = session.trace.times
        fraction = (session.time - times[0]) / max(1, times[-1] - times[0])
        self.time_edit.setText(str(session.time))
        self.time_edit.setToolTip(f"{100 * fraction:.1f} % of the {len(times)} times")
        self.progress.set_fraction(fraction)
        self.events = read_memory_events(session)
        self._render_events()

    def _render_events(self) -> None:
        palette = self.palette()
        muted = theme.muted(
            palette.color(QPalette.ColorRole.Window),
            palette.color(QPalette.ColorRole.WindowText),
        )
        accents = theme.accents()
        colors = {"read": accents.read, "write": accents.write}

        self.events_count.setText(str(len(self.events)))
        self.event_list.clear()
        for access in self.events:
            read = access.kind == "read"
            item = QTreeWidgetItem(
                [
                    "R" if read else "W",
                    format_address(access.addr),
                    size_text(access.size),
                ]
            )
            item.setForeground(0, colors[access.kind])
            item.setForeground(2, muted)
            for column in range(3):
                item.setToolTip(column, "Read" if read else "Written")
            self.event_list.addTopLevelItem(item)
        for column in range(3):
            self.event_list.resizeColumnToContents(column)

    def on_step(self, step: Step, checked: bool = False) -> None:
        step.go(self.session)

    def on_time_edit(self) -> None:
        try:
            new_time = int(self.time_edit.text(), 0)
        except ValueError:
            self.time_edit.setText(str(self.session.time))
            return

        self.session.goto(new_time)
        # 'goto' may clamp the new value
        self.time_edit.setText(str(self.session.time))

    # theme

    def on_palette_change(self) -> None:
        super().on_palette_change()
        self._update_label_colors()
        self._render_events()

    def _update_label_colors(self) -> None:
        palette = self.palette()
        background = palette.color(QPalette.ColorRole.Window)
        text = palette.color(QPalette.ColorRole.WindowText)
        muted = theme.muted(background, text)
        for label in (self.modules, self.events_title):
            label.setStyleSheet(f"color: {muted.name()}")
        # a badge: the number stands apart from the title
        badge = theme.blend(background, text, 0.12)
        self.events_count.setStyleSheet(
            f"background: {badge.name()}; color: {text.name()};"
            " border-radius: 7px; padding: 0 6px;"
        )

    # actions

    def _access(self, item: QTreeWidgetItem | None) -> MemoryAccess | None:
        if item is None:
            return None
        return self.events[self.event_list.indexOfTopLevelItem(item)]

    def on_event_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """A ctrl click jumps in the IDA view"""
        modifiers = QApplication.keyboardModifiers()
        access = self._access(item)
        if access is None or not modifiers & Qt.KeyboardModifier.ControlModifier:
            return
        ea = self.session.to_idb_addr(access.addr)
        if ea is not None:
            ida_kernwin.jumpto(ea)

    def on_event_double_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        access = self._access(item)
        if access is not None:
            self.follow_in_last_memory.emit(access.addr)

    def show_context_menu(self, pos: QPoint) -> None:
        item = self.event_list.itemAt(pos)
        access = self._access(item)
        if access is None:
            return
        self.show_menu(
            self.context_menu(access),
            self.event_list.viewport().mapToGlobal(pos),
        )

    def context_menu(self, access: MemoryAccess) -> QMenu:
        menu = QMenu(self)
        self.add_copy_action(menu, "Copy Address", lambda: format_address(access.addr))
        self.add_copy_action(
            menu,
            "Copy Bytes",
            lambda: format_bytes(
                self.session.mem.read_with_unknowns(access.addr, access.size)
            ),
        )
        menu.addSeparator()
        self.add_follow_address_actions(menu, access.addr)
        return menu
