import functools
from dataclasses import dataclass, replace
from typing import Callable

from .qt.QtGui import (
    QPainter,
    QColor,
    QFont,
    QFontMetricsF,
    QWheelEvent,
    QResizeEvent,
    QPaintEvent,
    QKeyEvent,
    QMouseEvent,
    QPalette,
    QPen,
)
from .qt.QtWidgets import QDialog, QMenu
from .qt import mouse_position
from .qt.QtCore import Qt, QEvent, QRect, QPoint, QRectF, Signal

from .breakpoint import Breakpoint, BreakpointKind, earliest, latest
from .search import SearchDialog, SearchMode, SearchQuery
from .session import Session
from .utils import (
    ask_trace_address,
    format_address,
    format_ascii,
    format_bytes,
    format_hex,
)
from .widget import (
    MAX_ADDR,
    MAX_MENU_BYTES,
    FrinetWidget,
    monospace_font,
)
from . import theme
from frinet import MemoryAccess

# Inlined QT Constants
CustomContextMenu = Qt.ContextMenuPolicy.CustomContextMenu
Key_G = Qt.Key.Key_G

# time of an access of the range of the breakpoint, None if there is none
Finder = Callable[[Breakpoint], int | None]
# time of an access from the times of a read and of a write
Combiner = Callable[[int | None, int | None], int | None]


class SelectionModel:
    """Manages the state of the user's byte selection using an anchor and current position."""

    def __init__(self) -> None:
        # The exact byte address where the user first pressed the mouse down
        self.anchor: int | None = None
        # The byte address where the user is currently hovering while dragging
        self.current: int | None = None
        # The range before the last press: the first click of a double click replaces it
        self.pressed_range: tuple[int, int] | None = None

    def handle_press(self, address: int | None) -> bool:
        self.pressed_range = self.get_range()
        if address is not None:
            # Start a new selection at the targeted byte
            self.anchor = address
            self.current = address
            return True
        else:
            # Clicking outside a valid byte resets the selection
            return self.clear()

    def select(self, address: int) -> None:
        """Selects the byte at the address"""
        self.anchor = address
        self.current = address

    def clear(self) -> bool:
        changed = self.anchor is not None
        self.anchor = None
        self.current = None
        return changed

    def handle_move(self, address: int | None) -> bool:
        if self.anchor is not None and address is not None:
            if self.current != address:
                self.current = address
                return True
        return False

    def handle_release(self, address: int | None) -> bool:
        return False

    def get_range(self) -> tuple[int, int] | None:
        if self.anchor is not None and self.current is not None:
            return min(self.anchor, self.current), max(self.anchor, self.current)
        return None


@dataclass(frozen=True)
class CellStyle:
    """Defines visual styling properties (background, text color, and borders) for a memory cell."""

    bg_color: QColor | None = None
    text_color: QColor | None = None
    border_left: QColor | None = None
    border_top: QColor | None = None
    border_right: QColor | None = None
    border_bottom: QColor | None = None


# style of the cells without one: shared, a CellStyle is frozen
PLAIN_CELL = CellStyle()


@dataclass
class MemoryColors:
    """
    Colors of the widget, from its palette: IDA sets it from the theme, and
    the widget builds them again on a palette change
    """

    background: QColor
    text: QColor
    # bytes that the trace does not know
    unknown: QColor
    address_background: QColor
    divider: QColor
    selection: QColor
    selection_text: QColor
    # borders of the accesses at the current time and of the breakpoints
    read: QColor
    write: QColor
    access: QColor
    read_breakpoint: QColor
    write_breakpoint: QColor
    access_breakpoint: QColor

    @staticmethod
    def from_palette(palette: QPalette) -> "MemoryColors":
        background = palette.color(QPalette.ColorRole.Base)
        text = palette.color(QPalette.ColorRole.Text)
        accents = theme.accents()
        read, write, access = accents.read, accents.write, accents.access
        return MemoryColors(
            background=background,
            text=text,
            unknown=theme.muted(background, text),
            address_background=theme.panel(background, text),
            divider=theme.blend(background, text, 0.25),
            selection=palette.color(QPalette.ColorRole.Highlight),
            selection_text=palette.color(QPalette.ColorRole.HighlightedText),
            read=read,
            write=write,
            access=access,
            read_breakpoint=theme.blend(background, read, 0.2),
            write_breakpoint=theme.blend(background, write, 0.2),
            access_breakpoint=theme.blend(background, access, 0.2),
        )

    def breakpoint(self, kind: BreakpointKind) -> tuple[QColor, QColor]:
        """(border, background) of a breakpoint"""
        return {
            BreakpointKind.READ: (self.read, self.read_breakpoint),
            BreakpointKind.WRITE: (self.write, self.write_breakpoint),
            BreakpointKind.ACCESS: (self.access, self.access_breakpoint),
        }[kind]


@dataclass(frozen=True)
class PanelPlan:
    """Defines the horizontal geometric boundaries (x and width) for a specific rendering panel."""

    x: float
    width: float


@dataclass(frozen=True)
class MemoryGeometry:
    """
    Where the view draws: a pure function of the font and of the widget rect,
    it never reads the trace. A font change and a resize invalidate it.
    """

    viewport_rect: QRect
    num_bytes_per_line: int
    pointer_size: int

    char_width: float
    char_height: float
    char_descent: float

    # lines the height fits, before the end of the address space clamps them
    capacity_lines: int

    addr_panel: PanelPlan
    hex_panel: PanelPlan
    ascii_panel: PanelPlan

    total_width: float

    @staticmethod
    def compute(
        font: QFont,
        rect: QRect,
        num_bytes_per_line: int,
        pointer_size: int,
        hex_painter: "GridPainter",
        ascii_painter: "GridPainter",
    ) -> "MemoryGeometry":
        fm = QFontMetricsF(font)
        char_width: float = fm.horizontalAdvance("9")
        char_height: float = fm.tightBoundingRect("9").height() * 1.75
        # from the top of the cell down to the baseline: the digits in its middle
        char_descent: float = char_height / 2 - fm.tightBoundingRect("9").center().y()

        capacity_lines: int = 0
        if char_height > 0:
            capacity_lines = int((rect.height() // char_height) + 1)

        addr_chars = pointer_size * 2
        addr_width = (addr_chars + 1) * char_width
        addr_panel = PanelPlan(x=char_width / 2, width=addr_width)

        hex_x = addr_panel.width + char_width
        hex_width = hex_painter.grid_width(char_width, num_bytes_per_line)
        hex_panel = PanelPlan(x=hex_x, width=hex_width)

        ascii_x = hex_panel.x + hex_panel.width + char_width
        ascii_width = ascii_painter.grid_width(char_width, num_bytes_per_line)
        ascii_panel = PanelPlan(x=ascii_x, width=ascii_width)

        return MemoryGeometry(
            viewport_rect=rect,
            num_bytes_per_line=num_bytes_per_line,
            pointer_size=pointer_size,
            char_width=char_width,
            char_height=char_height,
            char_descent=char_descent,
            capacity_lines=capacity_lines,
            addr_panel=addr_panel,
            hex_panel=hex_panel,
            ascii_panel=ascii_panel,
            total_width=ascii_panel.x + ascii_panel.width + char_width * 2,
        )

    def num_lines(self, base_addr: int) -> int:
        """Lines from `base_addr`: the height fits more when the space ends"""
        return min(
            self.capacity_lines, (MAX_ADDR - base_addr) // self.num_bytes_per_line
        )

    @property
    def ascii_divider_x(self) -> float:
        return self.hex_panel.x + self.hex_panel.width


@dataclass(frozen=True)
class MemoryContent:
    """
    What the view draws: the answers of the trace over the visible range, the
    only part of a paint that queries it. Its key invalidates it: a scroll
    moves `base_addr`, a resize changes `num_lines`, and the accesses and the
    content both follow the time.
    """

    base_addr: int
    num_lines: int
    # content of `base_addr` ..= `last_addr`, None for the unknown bytes
    values: list[int | None]
    # inclusive ranges the instruction at the time of the view reads and writes
    read_ranges: list[tuple[int, int]]
    write_ranges: list[tuple[int, int]]

    @staticmethod
    def empty(base_addr: int) -> "MemoryContent":
        """Content of a view without a single line, which asks the trace nothing"""
        return MemoryContent(base_addr, 0, [], [], [])

    @property
    def last_addr(self) -> int:
        """Last visible address, `base_addr - 1` when no line is visible"""
        return self.base_addr + len(self.values) - 1


@dataclass(frozen=True)
class PaintPlan:
    """
    The three natures of a paint, assembled: the geometry of the view, its
    content and its colors, with the cell styles the last two give.
    """

    geometry: MemoryGeometry
    content: MemoryContent
    colors: MemoryColors
    cell_styles: dict[int, CellStyle]


def apply_range_border(
    styles: dict[int, CellStyle],
    start_addr: int,
    end_addr: int,
    color: QColor,
    base_addr: int,
    last_addr: int,
    bytes_per_line: int,
) -> None:
    visible_start = max(start_addr, base_addr)
    visible_end = min(end_addr, last_addr)

    for addr in range(visible_start, visible_end + 1):
        offset = addr - base_addr

        is_start = addr == start_addr
        is_end = addr == end_addr
        is_line_start = addr % bytes_per_line == 0
        is_line_end = addr % bytes_per_line == bytes_per_line - 1

        left = is_start or is_line_start
        right = is_end or is_line_end
        top = addr - bytes_per_line < start_addr
        bottom = addr + bytes_per_line > end_addr

        if left or right or top or bottom:
            updates = {}
            if left:
                updates["border_left"] = color
            if right:
                updates["border_right"] = color
            if top:
                updates["border_top"] = color
            if bottom:
                updates["border_bottom"] = color

            styles[offset] = replace(styles.get(offset, PLAIN_CELL), **updates)


def cell_styles(
    geometry: MemoryGeometry,
    content: MemoryContent,
    colors: MemoryColors,
    breakpoints: list[Breakpoint],
    selection: tuple[int, int] | None,
) -> dict[int, CellStyle]:
    """
    Style of the cells that have one, by offset from `content.base_addr`: a
    pure function of the content, of the breakpoints and of the selection
    """
    styles: dict[int, CellStyle] = {}
    base_addr, last_addr = content.base_addr, content.last_addr
    bytes_per_line = geometry.num_bytes_per_line

    # 1. Breakpoints (Pale backgrounds + Borders)
    for breakpoint in breakpoints:
        border_color, bg_color = colors.breakpoint(breakpoint.kind)

        breakpoint_start = max(breakpoint.addr_min, base_addr)
        breakpoint_end = min(breakpoint.addr_max, last_addr)

        for addr in range(breakpoint_start, breakpoint_end + 1):
            offset = addr - base_addr
            styles[offset] = replace(styles.get(offset, PLAIN_CELL), bg_color=bg_color)

        apply_range_border(
            styles=styles,
            start_addr=breakpoint.addr_min,
            end_addr=breakpoint.addr_max,
            color=border_color,
            base_addr=base_addr,
            last_addr=last_addr,
            bytes_per_line=bytes_per_line,
        )

    # 2. Selection Range (Overrides breakpoint background/text colors)
    if selection:
        sel_min, sel_max = selection
        for addr in range(max(sel_min, base_addr), min(sel_max, last_addr) + 1):
            offset = addr - base_addr
            styles[offset] = replace(
                styles.get(offset, PLAIN_CELL),
                bg_color=colors.selection,
                text_color=colors.selection_text,
            )

    # 3. Accesses of the instruction at the time of the view (Borders)
    for ranges, color in [
        (content.read_ranges, colors.read),
        (content.write_ranges, colors.write),
    ]:
        for start_addr, end_addr in ranges:
            apply_range_border(
                styles=styles,
                start_addr=start_addr,
                end_addr=end_addr,
                color=color,
                base_addr=base_addr,
                last_addr=last_addr,
                bytes_per_line=bytes_per_line,
            )

    return styles


class AddressPainter:
    """Renders the memory addresses column on the left side of the widget."""

    def paint(self, painter: QPainter, plan: PaintPlan, start_x: float) -> None:
        geometry, content = plan.geometry, plan.content

        painter.setPen(plan.colors.text)
        address_fmt: str = "%016X" if geometry.pointer_size == 8 else "%08X"

        for line_idx in range(content.num_lines):
            y: float = (line_idx + 1) * geometry.char_height
            address: int = content.base_addr + line_idx * geometry.num_bytes_per_line
            painter.drawText(int(start_x), int(y), address_fmt % address)


class GridPainter:
    """Renders a grid of memory cells, adaptable for either hexadecimal or ASCII representations."""

    def __init__(
        self,
        cell_chars_count: int,
        cell_x_padding: float,
        formatter: Callable[[int | None], str],
    ) -> None:
        self.cell_chars_count = cell_chars_count
        self.cell_x_padding = cell_x_padding
        self.formatter = formatter

    def cell_width(self, char_width: float) -> float:
        return (self.cell_chars_count + self.cell_x_padding * 2) * char_width

    def grid_width(self, char_width: float, num_cells: int) -> float:
        return self.cell_width(char_width) * num_cells

    def paint(self, painter: QPainter, plan: PaintPlan, grid_plan: PanelPlan) -> None:
        geometry, content = plan.geometry, plan.content
        cell_width = self.cell_width(geometry.char_width)
        values = content.values

        # First Pass: Paint backgrounds and text
        for grid_y in range(content.num_lines):
            y = (grid_y + 1) * geometry.char_height
            line_offset = grid_y * geometry.num_bytes_per_line

            for grid_x in range(geometry.num_bytes_per_line):
                offset = line_offset + grid_x

                cell_start_x = grid_plan.x + (grid_x * cell_width)
                text_x = cell_start_x + (self.cell_x_padding * geometry.char_width)

                val = values[offset]
                style = plan.cell_styles.get(offset, PLAIN_CELL)

                if style.bg_color:
                    rect = QRectF(
                        cell_start_x,
                        y - geometry.char_descent,
                        cell_width,
                        geometry.char_height,
                    )
                    painter.fillRect(rect, style.bg_color)

                if style.text_color:
                    painter.setPen(style.text_color)
                else:
                    painter.setPen(
                        plan.colors.text if val is not None else plan.colors.unknown
                    )

                text = self.formatter(val)
                painter.drawText(int(text_x), int(y), text)

        # Second Pass: Paint borders
        for grid_y in range(content.num_lines):
            y = (grid_y + 1) * geometry.char_height
            line_offset = grid_y * geometry.num_bytes_per_line

            for grid_x in range(geometry.num_bytes_per_line):
                offset = line_offset + grid_x

                cell_start_x = grid_plan.x + (grid_x * cell_width)

                style = plan.cell_styles.get(offset, PLAIN_CELL)

                if (
                    style.border_left
                    or style.border_right
                    or style.border_top
                    or style.border_bottom
                ):
                    left_x = int(cell_start_x)
                    right_x = int(cell_start_x + cell_width)
                    top_y = int(y - geometry.char_descent)
                    bottom_y = int(y - geometry.char_descent + geometry.char_height)

                    if style.border_left:
                        painter.setPen(QPen(style.border_left, 0))
                        painter.drawLine(left_x, top_y, left_x, bottom_y)
                    if style.border_right:
                        painter.setPen(QPen(style.border_right, 0))
                        painter.drawLine(right_x, top_y, right_x, bottom_y)
                    if style.border_top:
                        painter.setPen(QPen(style.border_top, 0))
                        painter.drawLine(left_x, top_y, right_x, top_y)
                    if style.border_bottom:
                        painter.setPen(QPen(style.border_bottom, 0))
                        painter.drawLine(left_x, bottom_y, right_x, bottom_y)


class MemoryWidget(FrinetWidget):
    """The main UI component coordinating state, interactions, and the rendering pipeline for the hex editor."""

    focused = Signal()

    base_addr: int
    num_bytes_per_line: int
    pointer_size: int

    _addr_painter: AddressPainter
    _hex_painter: GridPainter
    _ascii_painter: GridPainter

    # the three natures of a paint, each cached until its own event
    _geometry: MemoryGeometry | None
    _content: MemoryContent | None
    # (base_addr, num_lines, time) the content answers
    _content_key: tuple[int, int, int] | None
    _colors: MemoryColors | None
    selection_model: SelectionModel

    def __init__(
        self, session: Session, memory_view_ids: Callable[[], list[int]]
    ) -> None:
        super().__init__(session, memory_view_ids)

        self.base_addr = 0
        self.num_bytes_per_line = 16
        self.pointer_size = session.pointer_size
        self._geometry = None
        self._content = None
        self._content_key = None
        self._colors = None
        self.selection_model = SelectionModel()

        self._addr_painter = AddressPainter()
        self._hex_painter = GridPainter(
            cell_chars_count=2,
            cell_x_padding=0.5,
            formatter=format_hex,
        )
        self._ascii_painter = GridPainter(
            cell_chars_count=1,
            cell_x_padding=0.0,
            formatter=format_ascii,
        )

        session.breakpoints_changed.connect(self.update)

        self.setup_ui()
        self.on_time_update()

    def setup_ui(self) -> None:
        self.setMouseTracking(True)
        # for the G shortcut
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setFont(monospace_font(10))

        self.setContextMenuPolicy(CustomContextMenu)
        self.customContextMenuRequested.connect(self._ctx_menu_handler)
        self._refresh_layout()

    def _address_at_pos(self, pos: QPoint) -> int | None:
        geometry = self._view_geometry()
        num_lines = geometry.num_lines(self.base_addr)
        if num_lines == 0:
            # no line fits: no byte is under the cursor, and char_height may be 0
            return None

        row = int(pos.y() // geometry.char_height)
        if row < 0 or row >= num_lines:
            return None

        x = pos.x()
        col = -1

        # Check hex panel intersection
        hex_panel, ascii_panel = geometry.hex_panel, geometry.ascii_panel
        if hex_panel.x <= x < (hex_panel.x + hex_panel.width):
            cell_width = self._hex_painter.cell_width(geometry.char_width)
            col = int((x - hex_panel.x) // cell_width)
        # Check ascii panel intersection
        elif ascii_panel.x <= x < (ascii_panel.x + ascii_panel.width):
            cell_width = self._ascii_painter.cell_width(geometry.char_width)
            col = int((x - ascii_panel.x) // cell_width)

        if 0 <= col < geometry.num_bytes_per_line:
            return self.base_addr + (row * geometry.num_bytes_per_line) + col

        return None

    def _ctx_menu_handler(self, position: QPoint) -> None:
        self.show_menu(self.context_menu(position), self.mapToGlobal(position))

    def context_menu(self, position: QPoint) -> QMenu:
        menu = QMenu(self)

        address = self._address_at_pos(position)
        sel_range = self.selection_model.get_range()
        breakpoint = self.session.breakpoint_at(address) if address is not None else None

        # Add selection-based breakpoint actions
        if sel_range:
            addr_min, addr_max = sel_range
            for kind, text in [
                (BreakpointKind.READ, "Break on reads"),
                (BreakpointKind.WRITE, "Break on writes"),
                (BreakpointKind.ACCESS, "Break on accesses"),
            ]:
                new_breakpoint = Breakpoint(kind=kind, addr_min=addr_min, addr_max=addr_max)
                self.add_action(
                    menu, text, functools.partial(self._add_breakpoint, new_breakpoint)
                )
            menu.addSeparator()

            self._add_goto_access_menus(menu, addr_min, addr_max)
            menu.addSeparator()

            if addr_max - addr_min + 1 <= MAX_MENU_BYTES:
                self._add_selection_actions(menu, addr_min, addr_max)
                menu.addSeparator()

        # Add breakpoint removal actions
        if breakpoint:
            self.add_action(
                menu,
                f"Remove {breakpoint.kind.value} breakpoint",
                functools.partial(self.session.remove_breakpoint, breakpoint),
            )
        if self.session.breakpoints:
            self.add_action(
                menu, "Clear memory breakpoints", self.session.clear_breakpoints
            )
            menu.addSeparator()

        # Standard context menu actions
        if address is not None:
            self.add_copy_action(
                menu,
                f"Copy address ({format_address(address)})",
                lambda: hex(address),
            )
            self.add_follow_address_actions(menu, self._pointer_at(address), "pointer")
            menu.addSeparator()

        self.add_action(menu, "Go to address...", self._prompt_goto_address)
        self.add_action(menu, "Search...", self._prompt_search)
        return menu

    def _add_selection_actions(self, menu: QMenu, addr_min: int, addr_max: int) -> None:
        """Copy and search the selected bytes"""
        size = addr_max - addr_min + 1

        def data() -> list[int | None]:
            return self.session.mem.read_with_unknowns(addr_min, size)

        def action_search() -> None:
            self._prompt_search(SearchQuery(SearchMode.HEX, format_bytes(data())))

        self.add_copy_action(menu, "Copy bytes (hex)", lambda: format_bytes(data()))
        self.add_copy_action( menu, "Copy bytes reversed (hex)", lambda: format_bytes(data()[::-1]))
        self.add_action(menu, "Search selected bytes...", action_search)

    def _add_goto_access_menus(self, menu: QMenu, addr_min: int, addr_max: int) -> None:
        """ Go to first / previous / next / final" submenus """
        trace = self.session.trace
        time = self.session.time
        finders: list[tuple[str, Finder, Combiner]] = [
            ("Go to first", lambda access: access.first_time(trace), earliest),
            ("Go to previous", lambda access: access.prev_time(trace, time), latest),
            ("Go to next", lambda access: access.next_time(trace, time), earliest),
            ("Go to final", lambda access: access.last_time(trace), latest),
        ]
        for text, find, combine in finders:
            submenu = menu.addMenu(text)
            submenu.aboutToShow.connect(
                functools.partial(
                    self._fill_goto_menu, submenu, find, combine, addr_min, addr_max
                )
            )

    def _fill_goto_menu(
        self,
        submenu: QMenu,
        find: Finder,
        combine: Combiner,
        addr_min: int,
        addr_max: int,
    ) -> None:
        """Read, Write and Access entries, disabled when there is none"""
        submenu.clear()
        # the accesses of the range are the hits of a breakpoint over it
        read, write = (
            find(Breakpoint(kind=kind, addr_min=addr_min, addr_max=addr_max))
            for kind in (BreakpointKind.READ, BreakpointKind.WRITE)
        )
        for label, found in [
            ("Read", read),
            ("Write", write),
            ("Access", combine(read, write)),
        ]:
            if found is None:
                submenu.addAction(label).setEnabled(False)
            else:
                self.add_action(
                    submenu, label, functools.partial(self.session.goto, found)
                )

    def _add_breakpoint(self, breakpoint: Breakpoint) -> None:
        self.selection_model.clear()
        self.session.add_breakpoint(breakpoint)

    def _toggle_access_breakpoint(self, addr_min: int, addr_max: int) -> None:
        """Removes the breakpoints over the range, or breaks on its accesses"""
        self.selection_model.clear()
        if not self.session.remove_breakpoints_over(addr_min, addr_max):
            self.session.add_breakpoint(
                Breakpoint(
                    kind=BreakpointKind.ACCESS, addr_min=addr_min, addr_max=addr_max
                )
            )

    def _pointer_at(self, address: int) -> int | None:
        """Little-endian pointer at the address, None if a byte is unknown"""
        if address > MAX_ADDR - self.pointer_size:
            return None
        values = self.session.mem.read_with_unknowns(address, self.pointer_size)
        known = [value for value in values if value is not None]
        if len(known) != len(values):
            return None
        return int.from_bytes(bytes(known), "little")

    def _prompt_goto_address(self) -> None:
        address = ask_trace_address(self.session, self.base_addr)
        if address is not None:
            self.goto_address(address)

    def goto_address(self, address: int) -> None:
        """Shows the line of the address at the top"""
        self._set_base_addr(address - address % self.num_bytes_per_line)
        self.update()

    def follow_address(self, address: int) -> None:
        """Shows the address at the top, the selection on its byte"""
        self.selection_model.select(address)
        self.goto_address(address)

    def focusInEvent(self, event) -> None:
        super().focusInEvent(event)
        self.focused.emit()

    def _set_base_addr(self, base_addr: int) -> None:
        max_base_addr = MAX_ADDR - self.num_bytes_per_line
        self.base_addr = min(max(0, base_addr), max_base_addr)

    def _prompt_search(self, query: SearchQuery | None = None) -> None:
        """Asks for a query, offering `query` or the last one, and searches it"""
        if query is None:
            query = self.session.last_search_query
        dialog = SearchDialog(self, query)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        query = dialog.query()
        self.session.last_search_query = query
        self.open_search_matches.emit(query.label, query.start(self.session.trace))

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            address = self._address_at_pos(mouse_position(event).toPoint())
            if self.selection_model.handle_press(address):
                self.update()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if event.buttons() & Qt.MouseButton.LeftButton:
            address = self._address_at_pos(mouse_position(event).toPoint())
            if self.selection_model.handle_move(address):
                self.update()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            address = self._address_at_pos(mouse_position(event).toPoint())
            if self.selection_model.handle_release(address):
                self.update()
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        """Toggles an access breakpoint on the selection under the cursor or the byte"""
        if event.button() != Qt.MouseButton.LeftButton:
            super().mouseDoubleClickEvent(event)
            return
        address = self._address_at_pos(mouse_position(event).toPoint())
        if address is not None:
            selection = self.selection_model.pressed_range
            if selection is None or not selection[0] <= address <= selection[1]:
                selection = (address, address)
            self._toggle_access_breakpoint(*selection)
            self.update()
        # not super(): it calls mousePressEvent

    def keyPressEvent(self, e: QKeyEvent) -> None:
        if e.key() == Key_G:
            self._prompt_goto_address()
            e.accept()
            return
        super().keyPressEvent(e)

    def _refresh_layout(self) -> None:
        """Width the panels need: the geometry gives it, without a query"""
        self._geometry = None
        self.setMinimumWidth(int(self._view_geometry().total_width))
        self.update()

    def on_time_update(self) -> None:
        self.update()

    def on_palette_change(self) -> None:
        self._colors = None
        self.update()

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if event.type() == QEvent.Type.FontChange:
            self._refresh_layout()

    def wheelEvent(self, event: QWheelEvent) -> None:
        # Check for Ctrl + Wheel to navigate breakpoint history
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            if event.angleDelta().y() == 0:
                return

            hover_address = self._address_at_pos(event.position().toPoint())
            if hover_address is None:
                return

            breakpoint = self.session.breakpoint_at(hover_address)
            if breakpoint is None:
                return

            time = self.session.time
            trace = self.session.trace
            if event.angleDelta().y() > 0:
                new_time = breakpoint.prev_time(trace, before=time)
            else:
                new_time = breakpoint.next_time(trace, after=time)

            if new_time is not None:
                self.session.goto(new_time)

            return

        # Normal scrolling behavior
        scroll_offset = self.num_bytes_per_line

        if event.angleDelta().y() > 0:
            self._set_base_addr(self.base_addr - scroll_offset)
        if event.angleDelta().y() < 0:
            self._set_base_addr(self.base_addr + scroll_offset)

        self.update()

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._refresh_layout()

    def _view_geometry(self) -> MemoryGeometry:
        """Layout of the view, from its font and its rect"""
        if self._geometry is None:
            self._geometry = MemoryGeometry.compute(
                font=self.font(),
                rect=self.rect(),
                num_bytes_per_line=self.num_bytes_per_line,
                pointer_size=self.pointer_size,
                hex_painter=self._hex_painter,
                ascii_painter=self._ascii_painter,
            )
        return self._geometry

    def _view_content(self, geometry: MemoryGeometry) -> MemoryContent:
        """Memory and accesses of the view, asked again when its key changes"""
        num_lines = geometry.num_lines(self.base_addr)
        key = (self.base_addr, num_lines, self.session.time)
        if self._content is None or self._content_key != key:
            self._content = self._fetch_content(geometry, self.base_addr, num_lines)
            self._content_key = key
        return self._content

    def _fetch_content(
        self, geometry: MemoryGeometry, base_addr: int, num_lines: int
    ) -> MemoryContent:
        """The lines the geometry asks for: a painter draws every byte of them"""
        if num_lines == 0:
            # the view is too short for a line: it has nothing to ask
            return MemoryContent.empty(base_addr)

        size = num_lines * geometry.num_bytes_per_line
        mem = self.session.mem
        return MemoryContent(
            base_addr=base_addr,
            num_lines=num_lines,
            values=mem.read_with_unknowns(base_addr, size),
            read_ranges=continious_ranges_from_accesses(mem.reads(base_addr, size)),
            write_ranges=continious_ranges_from_accesses(mem.writes(base_addr, size)),
        )

    def _view_colors(self) -> MemoryColors:
        """Colors of the view, from its palette"""
        if self._colors is None:
            self._colors = MemoryColors.from_palette(self.palette())
        return self._colors

    def _paint_plan(self) -> PaintPlan:
        geometry = self._view_geometry()
        content = self._view_content(geometry)
        colors = self._view_colors()
        return PaintPlan(
            geometry=geometry,
            content=content,
            colors=colors,
            cell_styles=cell_styles(
                geometry=geometry,
                content=content,
                colors=colors,
                breakpoints=self.session.breakpoints,
                selection=self.selection_model.get_range(),
            ),
        )

    def paintEvent(self, event: QPaintEvent) -> None:
        plan = self._paint_plan()
        geometry, colors = plan.geometry, plan.colors
        rect = geometry.viewport_rect

        painter = QPainter(self)
        painter.fillRect(event.rect(), colors.background)

        address_area_rect = QRect(
            0, rect.top(), int(geometry.addr_panel.width), rect.height()
        )
        painter.fillRect(address_area_rect, colors.address_background)

        painter.setPen(colors.divider)
        for divider_x in (geometry.addr_panel.width, geometry.ascii_divider_x):
            painter.drawLine(int(divider_x), rect.top(), int(divider_x), rect.height())

        self._addr_painter.paint(painter, plan, geometry.addr_panel.x)
        self._hex_painter.paint(painter, plan, geometry.hex_panel)
        self._ascii_painter.paint(painter, plan, geometry.ascii_panel)


def continious_ranges_from_accesses(
    accesses: list[MemoryAccess],
) -> list[tuple[int, int]]:
    """Inclusive (start, end) ranges covered by the accesses"""
    ranges: list[tuple[int, int]] = []

    for access in sorted(accesses, key=lambda access: access.addr):
        end = access.addr + access.size - 1
        if ranges and access.addr <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end))
        else:
            ranges.append((access.addr, end))

    return ranges
