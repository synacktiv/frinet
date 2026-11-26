from dataclasses import dataclass, replace
from typing import Callable, Optional, Sequence

from PySide6.QtGui import (
    QPainter,
    QColor,
    QFontMetricsF,
    QFont,
    QWheelEvent,
    QResizeEvent,
    QPaintEvent,
    QAction,
    QKeyEvent,
    QGuiApplication,
    QMouseEvent,
)
from PySide6.QtWidgets import (
    QAbstractScrollArea,
    QMenu,
    QInputDialog,
    QVBoxLayout,
    QDialog,
    QLineEdit,
    QLabel,
    QCheckBox,
    QDialogButtonBox,
)
from PySide6.QtCore import Qt, QRect, QPoint, QRectF

from core import Ctx
from frinet_db import MemNode

# Inlined QT Constants
ScrollBarAlwaysOff = Qt.ScrollBarPolicy.ScrollBarAlwaysOff
Monospace = QFont.StyleHint.Monospace
LightGray = Qt.GlobalColor.lightGray
White = Qt.GlobalColor.white
Black = Qt.GlobalColor.black
Gray = Qt.GlobalColor.gray
CustomContextMenu = Qt.ContextMenuPolicy.CustomContextMenu
Key_G = Qt.Key.Key_G


@dataclass
class Breakpoint:
    """Represents a memory breakpoint over a specific range of addresses."""

    read: bool
    addr_min: int
    addr_max: int


class SelectionModel:
    """Manages the state of the user's byte selection using an anchor and current position."""

    def __init__(self) -> None:
        # The exact byte address where the user first pressed the mouse down
        self.anchor: Optional[int] = None
        # The byte address where the user is currently hovering while dragging
        self.current: Optional[int] = None

    def handle_press(self, address: Optional[int]) -> bool:
        if address is not None:
            # Start a new selection at the targeted byte
            self.anchor = address
            self.current = address
            return True
        else:
            # Clicking outside a valid byte resets the selection
            changed = self.anchor is not None
            self.anchor = None
            self.current = None
            return changed

    def handle_move(self, address: Optional[int]) -> bool:
        if self.anchor is not None and address is not None:
            if self.current != address:
                self.current = address
                return True
        return False

    def handle_release(self, address: Optional[int]) -> bool:
        return False

    def get_range(self) -> Optional[tuple[int, int]]:
        if self.anchor is not None and self.current is not None:
            return min(self.anchor, self.current), max(self.anchor, self.current)
        return None


@dataclass
class CellStyle:
    """Defines visual styling properties (background, text color, and borders) for a memory cell."""

    bg_color: Optional[QColor] = None
    text_color: Optional[QColor] = None
    border_left: Optional[QColor] = None
    border_top: Optional[QColor] = None
    border_right: Optional[QColor] = None
    border_bottom: Optional[QColor] = None

    def derive_with(self, other: Optional["CellStyle"]) -> "CellStyle":
        if not other:
            return self
        return CellStyle(
            bg_color=other.bg_color or self.bg_color,
            text_color=other.text_color or self.text_color,
            border_left=other.border_left or self.border_left,
            border_top=other.border_top or self.border_top,
            border_right=other.border_right or self.border_right,
            border_bottom=other.border_bottom or self.border_bottom,
        )


SELECTION_STYLE = CellStyle(
    bg_color=QColor(0, 120, 215),
    text_color=QColor(255, 255, 255),
)


@dataclass
class PanelPlan:
    """Defines the horizontal geometric boundaries (x and width) for a specific rendering panel."""

    x: float
    width: float


@dataclass
class PaintPlan:
    """Aggregates all geometric and styling calculations required for a single paint cycle."""

    viewport_rect: QRect
    base_addr: int
    num_lines: int
    num_bytes_per_line: int
    pointer_size: int

    char_width: float
    char_height: float
    char_descent: float

    addr_panel: PanelPlan
    hex_panel: PanelPlan
    ascii_panel: PanelPlan

    total_width: float

    default_cell_style: CellStyle
    cell_styles: dict[int, CellStyle]


class AddressPainter:
    """Renders the memory addresses column on the left side of the widget."""

    def paint(self, painter: QPainter, plan: PaintPlan, start_x: float) -> None:
        painter.setPen(Black)
        address_fmt: str = "%016X" if plan.pointer_size == 8 else "%08X"

        for line_idx in range(plan.num_lines):
            y: float = (line_idx + 1) * plan.char_height
            address: int = plan.base_addr + (line_idx * plan.num_bytes_per_line)
            painter.drawText(int(start_x), int(y), address_fmt % address)


class GridPainter:
    """Renders a grid of memory cells, adaptable for either hexadecimal or ASCII representations."""

    def __init__(
        self,
        cell_chars_count: int,
        cell_x_padding: float,
        formatter: Callable[[Optional[int]], str],
    ) -> None:
        self.cell_chars_count = cell_chars_count
        self.cell_x_padding = cell_x_padding
        self.formatter = formatter

    def cell_width(self, char_width: float) -> float:
        return (self.cell_chars_count + self.cell_x_padding * 2) * char_width

    def grid_width(self, char_width: float, num_cells: int) -> float:
        return self.cell_width(char_width) * num_cells

    def paint(
        self,
        painter: QPainter,
        plan: PaintPlan,
        grid_plan: PanelPlan,
        data: Sequence[Optional[int]],
    ) -> None:
        cell_width = self.cell_width(plan.char_width)

        # First Pass: Paint backgrounds and text
        for grid_y in range(plan.num_lines):
            y = (grid_y + 1) * plan.char_height
            line_offset = grid_y * plan.num_bytes_per_line

            for grid_x in range(plan.num_bytes_per_line):
                offset = line_offset + grid_x

                cell_start_x = grid_plan.x + (grid_x * cell_width)
                text_x = cell_start_x + (self.cell_x_padding * plan.char_width)

                val = data[offset] if offset < len(data) else None
                specific_style = plan.cell_styles.get(offset, None)
                style = plan.default_cell_style.derive_with(specific_style)

                if style.bg_color:
                    rect = QRectF(
                        cell_start_x,
                        y - plan.char_descent,
                        cell_width,
                        plan.char_height,
                    )
                    painter.fillRect(rect, style.bg_color)

                if style.text_color:
                    painter.setPen(style.text_color)
                else:
                    painter.setPen(Black if val is not None else Gray)

                text = self.formatter(val)
                painter.drawText(int(text_x), int(y), text)

        # Second Pass: Paint borders
        for grid_y in range(plan.num_lines):
            y = (grid_y + 1) * plan.char_height
            line_offset = grid_y * plan.num_bytes_per_line

            for grid_x in range(plan.num_bytes_per_line):
                offset = line_offset + grid_x

                cell_start_x = grid_plan.x + (grid_x * cell_width)

                specific_style = plan.cell_styles.get(offset, None)
                style = plan.default_cell_style.derive_with(specific_style)

                if (
                    style.border_left
                    or style.border_right
                    or style.border_top
                    or style.border_bottom
                ):
                    left_x = int(cell_start_x)
                    right_x = int(cell_start_x + cell_width)
                    top_y = int(y - plan.char_descent)
                    bottom_y = int(y - plan.char_descent + plan.char_height)

                    if style.border_left:
                        painter.setPen(style.border_left)
                        painter.drawLine(left_x, top_y, left_x, bottom_y)
                    if style.border_right:
                        painter.setPen(style.border_right)
                        painter.drawLine(right_x, top_y, right_x, bottom_y)
                    if style.border_top:
                        painter.setPen(style.border_top)
                        painter.drawLine(left_x, top_y, right_x, top_y)
                    if style.border_bottom:
                        painter.setPen(style.border_bottom)
                        painter.drawLine(left_x, bottom_y, right_x, bottom_y)


def format_hex(val: Optional[int]) -> str:
    return "%02X" % val if val is not None else "??"


def format_ascii(val: Optional[int]) -> str:
    return chr(val) if val is not None and 0x20 <= val <= 0x7E else "."


class MemoryWidget(QAbstractScrollArea):
    """The main UI component coordinating state, interactions, and the rendering pipeline for the hex editor."""

    ctx: Ctx
    base_addr: int
    num_bytes_per_line: int
    pointer_size: int
    breakpoints: list[Breakpoint]

    _addr_painter: AddressPainter
    _hex_painter: GridPainter
    _ascii_painter: GridPainter

    _action_goto: QAction
    _action_copy_address: QAction
    _action_break_read: QAction
    _action_break_write: QAction
    _action_remove_bp: QAction

    _last_plan: Optional[PaintPlan]
    selection_model: SelectionModel

    def __init__(self, ctx: Ctx) -> None:
        super().__init__()

        self.ctx = ctx
        self.ctx.register_time_observer(self)

        self.base_addr = 0
        self.num_bytes_per_line = 16
        self.pointer_size = 8
        self.breakpoints = []
        self.follow_accesses = True   # jump to the bytes read/written at the current time
        self._last_plan = None
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

        self.setup_ui()
        self.on_time_update()

    def close(self) -> bool:
        is_closed: bool = super().close()
        if is_closed:
            self.ctx.unregister_time_observer(self)
        return is_closed

    def setup_ui(self) -> None:
        self.setVerticalScrollBarPolicy(ScrollBarAlwaysOff)
        self.setMouseTracking(True)

        font = QFont("monospace", 10)
        font.setStyleHint(Monospace)
        self.setFont(font)

        self._init_ctx_menu()
        self._refresh_layout()

    def _init_ctx_menu(self) -> None:
        self.setContextMenuPolicy(CustomContextMenu)
        self.customContextMenuRequested.connect(self._ctx_menu_handler)

        self._action_goto = QAction("Go to address...", self)
        self._action_search = QAction("Search...", self)
        self._action_copy_address = QAction("Copy address", self)
        self._action_break_read = QAction("Break on reads", self)
        self._action_break_write = QAction("Break on writes", self)
        self._action_remove_bp = QAction("Remove breakpoint", self)
        self._action_follow = QAction("Follow memory accesses", self)
        self._action_follow.setCheckable(True)
        self._action_follow.setChecked(self.follow_accesses)

    def get_first_breakpoint_at(self, address: int) -> Optional[Breakpoint]:
        """Returns the first breakpoint matching the given address."""
        for bp in self.breakpoints:
            if bp.addr_min <= address <= bp.addr_max:
                return bp
        return None

    def _address_at_pos(self, pos: QPoint) -> Optional[int]:
        if not self._last_plan:
            return None

        plan = self._last_plan
        row = int(pos.y() // plan.char_height)
        if row < 0 or row >= plan.num_lines:
            return None

        x = pos.x()
        col = -1

        # Check hex panel intersection
        if plan.hex_panel.x <= x < (plan.hex_panel.x + plan.hex_panel.width):
            cell_width = self._hex_painter.cell_width(plan.char_width)
            col = int((x - plan.hex_panel.x) // cell_width)
        # Check ascii panel intersection
        elif plan.ascii_panel.x <= x < (plan.ascii_panel.x + plan.ascii_panel.width):
            cell_width = self._ascii_painter.cell_width(plan.char_width)
            col = int((x - plan.ascii_panel.x) // cell_width)

        if 0 <= col < plan.num_bytes_per_line:
            return plan.base_addr + (row * plan.num_bytes_per_line) + col

        return None

    def _ctx_menu_handler(self, position: QPoint) -> None:
        menu = QMenu(self)

        address = self._address_at_pos(position)
        sel_range = self.selection_model.get_range()
        bp = self.get_first_breakpoint_at(address) if address is not None else None

        # Add selection-based breakpoint actions
        if sel_range:
            menu.addAction(self._action_break_read)
            menu.addAction(self._action_break_write)
            menu.addSeparator()

        # Add breakpoint removal action
        if bp:
            bp_type = "read" if bp.read else "write"
            self._action_remove_bp.setText(f"Remove {bp_type} breakpoint")
            menu.addAction(self._action_remove_bp)
            menu.addSeparator()

        # Standard context menu actions
        if address is not None:
            address_fmt = "0x%016X" if self.pointer_size == 8 else "0x%08X"
            self._action_copy_address.setText(f"Copy address ({address_fmt % address})")
            menu.addAction(self._action_copy_address)
            menu.addSeparator()

        menu.addAction(self._action_goto)
        menu.addAction(self._action_search)
        menu.addSeparator()
        menu.addAction(self._action_follow)

        action: Optional[QAction] = menu.exec(self.mapToGlobal(position))

        if action == self._action_follow:
            self.follow_accesses = self._action_follow.isChecked()
            if self.follow_accesses:
                self.on_time_update()
        elif action == self._action_goto:
            self._prompt_goto_address()
        elif action == self._action_search:
            self._prompt_search()
        elif action == self._action_copy_address and address is not None:
            QGuiApplication.clipboard().setText(hex(address))
        elif action == self._action_break_read and sel_range:
            self.breakpoints.append(
                Breakpoint(read=True, addr_min=sel_range[0], addr_max=sel_range[1])
            )
            self.selection_model.anchor = None
            self.selection_model.current = None
            self.viewport().update()
        elif action == self._action_break_write and sel_range:
            self.breakpoints.append(
                Breakpoint(read=False, addr_min=sel_range[0], addr_max=sel_range[1])
            )
            self.selection_model.anchor = None
            self.selection_model.current = None
            self.viewport().update()
        elif action == self._action_remove_bp and bp is not None:
            self.breakpoints.remove(bp)
            self.viewport().update()

    def _prompt_goto_address(self) -> None:
        text, ok = QInputDialog.getText(
            self, "Go to address", "Enter memory address (hex or decimal):"
        )
        if not ok or not text:
            return

        try:
            new_address: int = int(text, 0)
        except ValueError:
            return

        # Align to the nearest multiple of 16
        new_address -= new_address & 0xF
        self.base_addr = max(0, new_address)
        if self.viewport():
            self.viewport().update()

    def _prompt_search(self):
        dialog = SearchDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            text, is_regex = dialog.get_search_params()
            if not text:
                return
            self.ctx.search(text, is_regex)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            address = self._address_at_pos(event.position().toPoint())
            if self.selection_model.handle_press(address):
                self.viewport().update()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if event.buttons() & Qt.MouseButton.LeftButton:
            address = self._address_at_pos(event.position().toPoint())
            if self.selection_model.handle_move(address):
                self.viewport().update()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            address = self._address_at_pos(event.position().toPoint())
            if self.selection_model.handle_release(address):
                self.viewport().update()
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, e: QKeyEvent) -> None:
        if e.key() == Key_G:
            self._prompt_goto_address()
            e.accept()
            return
        super().keyPressEvent(e)

    def _refresh_layout(self) -> None:
        plan = self._create_paint_plan()
        self.setMinimumWidth(int(plan.total_width))

    def on_time_update(self) -> None:
        if self.follow_accesses:
            try:
                access = find_access_at(self.ctx.db.frinet_db, self.ctx.db.time)
            except Exception as err:
                print("[frinet] follow memory:", err)
                access = None
            if access is not None:
                addr, size, _is_write = access
                self.goto_address(addr, size)
                return
        if self.viewport():
            self.viewport().update()

    def goto_address(self, addr: int, size: int = 1) -> None:
        """Scroll to <addr> (two lines of context above) and select <size> bytes."""
        line = addr - (addr % self.num_bytes_per_line)
        self.base_addr = max(0, line - 2 * self.num_bytes_per_line)
        self.selection_model.anchor = addr
        self.selection_model.current = addr + max(1, size) - 1
        if self.viewport():
            self.viewport().update()

    def wheelEvent(self, event: QWheelEvent) -> None:
        # Check for Ctrl + Wheel to navigate breakpoint history
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            if event.angleDelta().y() == 0:
                return

            hover_address = self._address_at_pos(event.position().toPoint())
            if hover_address is None:
                return

            breakpoint = self.get_first_breakpoint_at(hover_address)
            if breakpoint is None:
                return

            time = self.ctx.db.time
            frinet_db = self.ctx.db.frinet_db

            if event.angleDelta().y() > 0:
                if breakpoint.read:
                    func = frinet_db.prev_mem_read
                else:
                    func = frinet_db.prev_mem_write
            else:
                if breakpoint.read:
                    func = frinet_db.next_mem_read
                else:
                    func = frinet_db.next_mem_write

            new_time = func(time, (breakpoint.addr_min, breakpoint.addr_max))
            if new_time is not None:
                self.ctx.set_time(new_time)

            return

        # Normal scrolling behavior
        scroll_offset = self.num_bytes_per_line

        if event.angleDelta().y() > 0:
            self.base_addr = self.base_addr - scroll_offset
        if event.angleDelta().y() < 0:
            self.base_addr = self.base_addr + scroll_offset

        if self.base_addr < 0:
            self.base_addr = 0

        if self.viewport():
            self.viewport().update()

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        self._refresh_layout()

    def _apply_range_border(
        self,
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
                if offset not in styles:
                    styles[offset] = CellStyle()

                updates = {}
                if left:
                    updates["border_left"] = color
                if right:
                    updates["border_right"] = color
                if top:
                    updates["border_top"] = color
                if bottom:
                    updates["border_bottom"] = color

                styles[offset] = replace(styles[offset], **updates)

    def _create_paint_plan(self) -> PaintPlan:
        font = self.font()
        fm = QFontMetricsF(font)
        char_width: float = fm.horizontalAdvance("9")
        char_height: float = fm.tightBoundingRect("9").height() * 1.75
        char_descent: float = char_height - fm.descent() * 0.75

        viewport = self.viewport()
        rect = viewport.rect() if viewport else QRect()

        num_lines: int = 0
        if char_height > 0:
            num_lines = int((rect.height() // char_height) + 1)
        last_addr = self.base_addr + (num_lines * self.num_bytes_per_line) - 1

        addr_chars = self.pointer_size * 2
        addr_width = (addr_chars + 1) * char_width
        addr_panel = PanelPlan(x=char_width / 2, width=addr_width)

        hex_x = addr_panel.width + char_width
        hex_width = self._hex_painter.grid_width(char_width, self.num_bytes_per_line)
        hex_panel = PanelPlan(x=hex_x, width=hex_width)

        ascii_divider_x = hex_panel.x + hex_panel.width
        ascii_x = ascii_divider_x + char_width
        ascii_width = self._ascii_painter.grid_width(
            char_width, self.num_bytes_per_line
        )
        ascii_panel = PanelPlan(x=ascii_x, width=ascii_width)

        total_width: float = ascii_panel.x + ascii_panel.width + char_width * 2

        default_cell_style = CellStyle()
        cell_styles: dict[int, CellStyle] = {}

        # 1. Paint Breakpoints (Pale backgrounds + Borders)
        for bp in self.breakpoints:
            border_color = QColor(0, 0, 255) if bp.read else QColor(255, 0, 0)
            bg_color = QColor(220, 220, 255) if bp.read else QColor(255, 220, 220)

            bp_start = max(bp.addr_min, self.base_addr)
            bp_end = min(bp.addr_max, last_addr)

            for addr in range(bp_start, bp_end + 1):
                offset = addr - self.base_addr
                if offset not in cell_styles:
                    cell_styles[offset] = CellStyle()
                cell_styles[offset] = replace(cell_styles[offset], bg_color=bg_color)

            self._apply_range_border(
                styles=cell_styles,
                start_addr=bp.addr_min,
                end_addr=bp.addr_max,
                color=border_color,
                base_addr=self.base_addr,
                last_addr=last_addr,
                bytes_per_line=self.num_bytes_per_line,
            )

        # 2. Paint Selection Range (Overrides breakpoint background/text colors)
        sel_range = self.selection_model.get_range()
        if sel_range:
            sel_min, sel_max = sel_range
            start_addr = max(sel_min, self.base_addr)
            end_addr = min(sel_max, last_addr)

            for addr in range(start_addr, end_addr + 1):
                offset = addr - self.base_addr
                if offset in cell_styles:
                    cell_styles[offset] = replace(
                        cell_styles[offset],
                        bg_color=SELECTION_STYLE.bg_color,
                        text_color=SELECTION_STYLE.text_color,
                    )
                else:
                    cell_styles[offset] = SELECTION_STYLE

        visible_addr_range = (self.base_addr, last_addr)

        time = self.ctx.db.time
        reads = self.ctx.db.frinet_db.memory_reads(time, visible_addr_range)
        writes = self.ctx.db.frinet_db.memory_writes(time, visible_addr_range)
        writes = list(filter(lambda node: node.time_min == time, writes))

        for start_addr, end_addr in continious_ranges_from_mem_nodes(reads):
            self._apply_range_border(
                styles=cell_styles,
                start_addr=start_addr,
                end_addr=end_addr,
                color=QColor(0, 0, 255),
                base_addr=self.base_addr,
                last_addr=last_addr,
                bytes_per_line=self.num_bytes_per_line,
            )

        for start_addr, end_addr in continious_ranges_from_mem_nodes(writes):
            self._apply_range_border(
                styles=cell_styles,
                start_addr=start_addr,
                end_addr=end_addr,
                color=QColor(255, 0, 0),
                base_addr=self.base_addr,
                last_addr=last_addr,
                bytes_per_line=self.num_bytes_per_line,
            )

        self._last_plan = PaintPlan(
            viewport_rect=rect,
            base_addr=self.base_addr,
            num_lines=num_lines,
            num_bytes_per_line=self.num_bytes_per_line,
            pointer_size=self.pointer_size,
            char_width=char_width,
            char_height=char_height,
            char_descent=char_descent,
            addr_panel=addr_panel,
            hex_panel=hex_panel,
            ascii_panel=ascii_panel,
            total_width=total_width,
            default_cell_style=default_cell_style,
            cell_styles=cell_styles,
        )
        return self._last_plan

    def paintEvent(self, event: QPaintEvent) -> None:
        if not self.viewport():
            return

        painter = QPainter(self.viewport())
        painter.fillRect(event.rect(), White)

        plan: PaintPlan = self._create_paint_plan()

        address_area_rect = QRect(
            0,
            plan.viewport_rect.top(),
            int(plan.addr_panel.width),
            plan.viewport_rect.height(),
        )
        painter.fillRect(address_area_rect, QColor(240, 240, 240))

        painter.setPen(LightGray)
        painter.drawLine(
            int(plan.addr_panel.width),
            plan.viewport_rect.top(),
            int(plan.addr_panel.width),
            plan.viewport_rect.height(),
        )

        ascii_divider_x = plan.hex_panel.x + plan.hex_panel.width
        painter.drawLine(
            int(ascii_divider_x),
            plan.viewport_rect.top(),
            int(ascii_divider_x),
            plan.viewport_rect.height(),
        )

        num_bytes_visible = plan.num_lines * plan.num_bytes_per_line
        data = self.ctx.db.memory_bytes(plan.base_addr, num_bytes_visible)

        self._addr_painter.paint(painter, plan, plan.addr_panel.x)
        self._hex_painter.paint(painter, plan, plan.hex_panel, data)
        self._ascii_painter.paint(painter, plan, plan.ascii_panel, data)


ADDR_MAX = (1 << 64) - 1


def _make_hit(func, t: int):
    """hit(lo, hi): does an access happen at exactly time t inside [lo, hi]?
    Works whether next_mem_* is inclusive or exclusive on time / range end."""
    def hit(lo: int, hi: int) -> bool:
        lo, hi = max(0, lo), min(ADDR_MAX, hi)
        if lo > hi:
            return False
        if t > 0 and func(t - 1, (lo, hi)) == t:
            return True
        return func(t, (lo, hi)) == t
    return hit


def find_access_at(frinet_db, t: int):
    """(addr, size, is_write) of the memory access done at time t, or None.
    Binary search over the address space with next_mem_write/next_mem_read
    (address ranges are inclusive, as frinet's own breakpoints use them)."""
    for func, is_write in ((frinet_db.next_mem_write, True), (frinet_db.next_mem_read, False)):
        hit = _make_hit(func, t)
        if not hit(0, ADDR_MAX):
            continue
        lo, hi = 0, ADDR_MAX            # first byte: smallest c with hit(0, c)
        while lo < hi:
            mid = (lo + hi) // 2
            if hit(0, mid):
                hi = mid
            else:
                lo = mid + 1
        start = lo
        lo, hi = start, ADDR_MAX        # last byte: largest c with hit(c, MAX)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if hit(mid, ADDR_MAX):
                lo = mid
            else:
                hi = mid - 1
        size = min(64, lo - start + 1)
        return start, size, is_write
    return None


def continious_ranges_from_mem_nodes(nodes: list[MemNode]) -> list[tuple[int, int]]:
    if len(nodes) == 0:
        return []

    nodes.sort(key=lambda node: node.addr_min)

    ranges = []

    start = nodes[0].addr_min
    end = nodes[0].addr_max

    for node in nodes[1:]:
        if node.addr_min == end + 1:
            end = node.addr_max
        else:
            ranges.append((start, end))
            start = node.addr_min
            end = node.addr_max

    ranges.append((start, end))

    return ranges


class SearchDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Search Memory")
        self.setMinimumWidth(300)

        layout = QVBoxLayout(self)

        self.search_input = QLineEdit(self)
        layout.addWidget(QLabel("Search pattern:"))
        layout.addWidget(self.search_input)

        self.regex_checkbox = QCheckBox("Use Regular Expression", self)
        layout.addWidget(self.regex_checkbox)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel,
            self,
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_search_params(self) -> tuple[str, bool]:
        return self.search_input.text(), self.regex_checkbox.isChecked()
