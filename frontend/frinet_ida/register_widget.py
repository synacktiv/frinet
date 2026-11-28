"""
The registers view: the value of every register at the time of the session,
the pinned registers first.

From the trace to the screen:
- `read_state` asks the trace and the IDB what a register is at this time,
- `value_html` writes its value as rich text, in the `RegisterColors`,
- `RegisterLine` is the widgets of its line, sized by `LineMetrics`,
- `RegistersWidget` builds the lines and gives them the states.
"""

import enum
import functools
import html
import itertools
from dataclasses import dataclass
from typing import Callable

import ida_funcs
import ida_kernwin
from frinet import Register

from . import glyph_icons, theme
from .glyph_icons import GlyphButtons
from .qt.QtCore import QPoint, QSize, Qt, Signal
from .qt.QtGui import QColor, QFont, QMouseEvent, QPainter, QPalette
from .qt.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QScrollArea,
    QToolButton,
    QVBoxLayout,
    QWidget,
)
from .session import Session
from .widget import FrinetWidget, monospace_font, polished_metrics

BAR_WIDTH = 3
SPACING = 4


# the state of a register at one time


class ValueKind(enum.Enum):
    """What a value of the size of a pointer points to"""

    # a function of the IDB
    FUNCTION = enum.auto()
    # memory the trace knows, at this time or another one
    MEMORY = enum.auto()
    NONE = enum.auto()


# none for the other values
VALUE_KIND_TOOLTIPS = {
    ValueKind.FUNCTION: "Code address",
    ValueKind.MEMORY: "Traced memory",
}


class Write(enum.Enum):
    """How the instruction at this time wrote the register"""

    NONE = enum.auto()
    SAME_VALUE = enum.auto()
    NEW_VALUE = enum.auto()


@dataclass(frozen=True)
class RegisterState:
    value: int | None
    # before the instruction at this time, when it wrote the register
    prev_value: int | None
    write: Write
    value_kind: ValueKind


def read_state(register: Register, session: Session) -> RegisterState:
    time = session.time
    value = register.value_at(time)
    if value is None:
        return RegisterState(None, None, Write.NONE, ValueKind.NONE)

    value_kind = read_value_kind(value, register.byte_size, session)
    # the first time gives every register its initial value: nothing to mark
    first = time == session.trace.times[0]
    if first or not register.is_write_at(time):
        return RegisterState(value, None, Write.NONE, value_kind)

    prev_value = register.value_at(time - 1)
    write = Write.SAME_VALUE if prev_value == value else Write.NEW_VALUE
    return RegisterState(value, prev_value, write, value_kind)


def read_value_kind(value: int, byte_size: int, session: Session) -> ValueKind:
    if byte_size != session.pointer_size:
        return ValueKind.NONE

    # in the module first: the code of a module is also memory of the trace
    ea = session.to_idb_addr(value)
    if ea is not None and ida_funcs.get_func(ea) is not None:
        return ValueKind.FUNCTION

    mem = session.mem
    try:
        known = (
            mem.read_with_unknowns(value, 1)[0] is not None
            or mem.prev_access(value, 1) is not None
            or mem.next_access(value, 1) is not None
        )
    except ValueError:
        # outside the address space
        return ValueKind.NONE
    return ValueKind.MEMORY if known else ValueKind.NONE


# the text of a value


@dataclass(frozen=True)
class RegisterColors:
    text: QColor
    muted: QColor
    value_kinds: dict[ValueKind, QColor]
    # background of the bytes the instruction changed
    changed_bytes: QColor
    bar: dict[Write, QColor | None]

    @staticmethod
    def from_palette(palette: QPalette) -> "RegisterColors":
        background = palette.color(QPalette.ColorRole.Window)
        text = palette.color(QPalette.ColorRole.WindowText)
        accents = theme.accents()
        return RegisterColors(
            text=text,
            muted=theme.muted(background, text),
            value_kinds={
                ValueKind.FUNCTION: accents.value_function,
                ValueKind.MEMORY: accents.value_memory,
                ValueKind.NONE: text,
            },
            changed_bytes=theme.blend(background, accents.register_write, 0.18),
            bar={
                Write.NONE: None,
                Write.SAME_VALUE: theme.blend(background, accents.register_write, 0.35),
                Write.NEW_VALUE: accents.register_write,
            },
        )


def hex_value(value: int, byte_size: int) -> str:
    return f"0x{value:0{2 * byte_size}x}"


def value_chars(byte_size: int, word_size: int, words_per_line: int) -> int:
    """Of the longest line of a value: "0x", then the words and their separators"""
    words = min(words_per_line, -(-byte_size // word_size))
    return 2 + words * (2 * word_size + 1) - 1


def span(text: str, color: QColor, background: QColor | None = None) -> str:
    style = f"color:{color.name()};"
    if background is not None:
        style += f"background-color:{background.name()};font-weight:bold;"
    return f'<span style="{style}">{html.escape(text)}</span>'


def value_html(
    state: RegisterState,
    byte_size: int,
    word_size: int,
    words_per_line: int,
    colors: RegisterColors,
) -> str:
    """
    Hex value in words of `word_size` bytes from the most significant one,
    `words_per_line` words by line: the leading zeros of a word muted, the bytes
    the instruction changed highlighted
    """
    assert state.value is not None
    color = colors.value_kinds[state.value_kind]
    digits = f"{state.value:0{2 * byte_size}x}"
    # without a previous value, nothing to compare the bytes with
    diff = 0 if state.prev_value is None else state.value ^ state.prev_value
    changed = [
        diff >> 8 * (byte_size - 1 - byte) & 0xFF != 0 for byte in range(byte_size)
    ]

    words = []
    for start in range(0, len(digits), 2 * word_size):
        word = digits[start : start + 2 * word_size]
        # the last digit of a word is never a leading zero
        zeros = min(len(word) - len(word.lstrip("0")), len(word) - 1)
        styles = [
            (index < zeros, changed[(start + index) // 2]) for index in range(len(word))
        ]
        # one span by run of digits of the same style
        parts = []
        index = 0
        for (muted, highlighted), run in itertools.groupby(styles):
            length = len(list(run))
            parts.append(
                span(
                    word[index : index + length],
                    colors.muted if muted else color,
                    colors.changed_bytes if highlighted else None,
                )
            )
            index += length
        words.append("".join(parts))

    lines = []
    for start in range(0, len(words), words_per_line):
        # continuation lines are aligned after "0x"
        prefix = span("0x" if start == 0 else "  ", color)
        lines.append(prefix + " ".join(words[start : start + words_per_line]))
    return f'<span style="white-space:pre">{"<br>".join(lines)}</span>'


# the widgets of a line


@dataclass(frozen=True)
class LineMetrics:
    """The sizes of the widgets of a line"""

    char_width: float
    line_height: int
    name_width: int
    button_width: int
    pointer_size: int
    # of the values up to the size of a pointer, their low bytes lined up
    small_value_width: int
    # above the separator of the pinned registers, to center it between the
    # lines: the names, the pins and the arrows reach the bottom of a line, the
    # digits leave its top empty
    separator_offset: int

    @staticmethod
    def measure(
        name_font: QFont,
        value_font: QFont,
        registers: list[Register],
        pointer_size: int,
        button_width: int,
    ) -> "LineMetrics":
        names = polished_metrics(name_font)
        values = polished_metrics(value_font)
        char_width = values.horizontalAdvance("0" * 100) / 100
        small_size = max(
            (reg.byte_size for reg in registers if reg.byte_size <= pointer_size),
            default=pointer_size,
        )
        digits = values.tightBoundingRect("0123456789abcdef")
        return LineMetrics(
            char_width=char_width,
            line_height=values.height(),
            name_width=max(
                (names.horizontalAdvance(r.name) for r in registers), default=0
            )
            + 2,
            button_width=button_width,
            pointer_size=pointer_size,
            small_value_width=text_width(
                char_width, value_chars(small_size, small_size, 1)
            ),
            separator_offset=max(0, values.ascent() + digits.top()),
        )

    @property
    def fixed_width(self) -> int:
        """Of a line but its value: the change bar, the three buttons, the name and the spacing"""
        return BAR_WIDTH + 3 * self.button_width + self.name_width + 6 * SPACING

    @property
    def line_width(self) -> int:
        return self.fixed_width + self.small_value_width

    def wide_value_width(self, byte_size: int, words_per_line: int) -> int:
        chars = value_chars(byte_size, self.pointer_size, words_per_line)
        return text_width(self.char_width, chars)

    def words_per_line(self, line_width: int) -> int:
        """Of the wide values, as many as a line of this width fits"""
        # a character of margin for the rounding of the widths
        chars = int((line_width - self.fixed_width) / self.char_width) - 1
        return max(1, (chars - 2) // (2 * self.pointer_size + 1))


def text_width(char_width: float, chars: int) -> int:
    """Of monospace text, a pixel of margin on each side for the rounding"""
    return round(char_width * chars) + 2


class ChangeBar(QWidget):
    """Thin mark of a register the instruction at this time wrote"""

    def __init__(self) -> None:
        super().__init__()
        self.setFixedWidth(BAR_WIDTH)
        self.color: QColor | None = None

    def set_color(self, color: QColor | None) -> None:
        self.color = color
        self.update()

    def paintEvent(self, event) -> None:
        if self.color is not None:
            QPainter(self).fillRect(self.rect(), self.color)


class ValueLabel(QLabel):
    """
    A value, selectable. When it is an address, a double click asks to follow it,
    a ctrl click to jump to it in the IDA view.
    """

    follow_requested = Signal(object)
    jump_requested = Signal(object)

    def __init__(self, font: QFont):
        super().__init__()
        self.address: int | None = None
        self.setFont(font)
        self.setTextFormat(Qt.TextFormat.RichText)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if (
            self.address is not None
            and event.button() == Qt.MouseButton.LeftButton
            and event.modifiers() & Qt.KeyboardModifier.ControlModifier
        ):
            self.jump_requested.emit(self.address)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event: QMouseEvent) -> None:
        if self.address is not None and event.button() == Qt.MouseButton.LeftButton:
            self.follow_requested.emit(self.address)
            event.accept()
            return
        super().mouseDoubleClickEvent(event)


@dataclass
class RegisterLine:
    register: Register
    # wider than a pointer: in words of the size of a pointer, as many by line
    # as the view fits
    wide: bool
    # the widgets below, side by side
    widget: QWidget
    bar: ChangeBar
    pin_button: QToolButton
    label: ValueLabel
    # set by `RegistersWidget.on_time_update`
    state: RegisterState | None = None


class RegistersWidget(FrinetWidget):
    # in the trace header order, like `Trace.regs`
    lines: list[RegisterLine]

    def __init__(self, session: Session, memory_view_ids: Callable[[], list[int]]):
        super().__init__(session, memory_view_ids)

        self.lines = []
        self.colors = RegisterColors.from_palette(self.palette())
        self.name_font = monospace_font(bold=True)
        self.value_font = monospace_font()
        # in a line of text: the lines stay as high as the values
        self.buttons = GlyphButtons(
            [glyph_icons.PIN, glyph_icons.PREV_CHANGE, glyph_icons.NEXT_CHANGE],
            self.value_font,
            glyph_icons.SMALL,
        )
        self.metrics = LineMetrics.measure(
            self.name_font,
            self.value_font,
            list(session.trace.regs.values()),
            session.pointer_size,
            self.buttons.size.width(),
        )
        # of the wide values, see `resizeEvent`
        self.words_per_line = 1

        self.setup_ui()
        session.pinned_registers_changed.connect(self.on_pinned_changed)
        self._update_pin_colors()
        self._set_words_per_line(self._fit_words_per_line())
        self.on_pinned_changed()
        self.on_time_update()

    # construction

    def setup_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # the lines, in the order of `_arrange_lines`
        self.content = QWidget()
        self.content.setMinimumWidth(self.metrics.line_width)
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(4, 0, 4, 0)
        self.content_layout.setSpacing(2)
        # between the pinned registers and the others
        rule = QFrame()
        rule.setFrameShape(QFrame.Shape.HLine)
        rule.setFrameShadow(QFrame.Shadow.Sunken)
        self.separator = QWidget()
        separator_layout = QVBoxLayout(self.separator)
        separator_layout.setContentsMargins(0, self.metrics.separator_offset, 0, 0)
        separator_layout.addWidget(rule)

        for register in self.session.trace.regs.values():
            self.lines.append(self._build_line(register))

        self.scroll = QScrollArea()
        self.scroll.setWidget(self.content)
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        # a constant viewport width: the scroll bar does not change the words by line
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        main_layout.addWidget(self.scroll)

    def _build_line(self, register: Register) -> RegisterLine:
        metrics = self.metrics

        name = QLabel(register.name)
        name.setFont(self.name_font)
        name.setFixedWidth(metrics.name_width)
        name.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        wide = register.byte_size > metrics.pointer_size
        label = ValueLabel(self.value_font)
        if wide:
            # its width follows the words by line, see `_set_words_per_line`
            label.setAlignment(
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
            )
        else:
            label.setFixedWidth(metrics.small_value_width)
            label.setAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            )

        pin_button = self.buttons.button(glyph_icons.PIN, "Pin")
        pin_button.setCheckable(True)
        # colored by the style sheet of `_update_pin_colors`
        pin_button.setObjectName("pin")
        prev_button = self.buttons.button(glyph_icons.PREV_CHANGE, "Previous write")
        next_button = self.buttons.button(glyph_icons.NEXT_CHANGE, "Next write")

        widget = QWidget()
        line = RegisterLine(register, wide, widget, ChangeBar(), pin_button, label)

        pin_button.clicked.connect(
            functools.partial(self.session.set_pinned, register.name)
        )
        prev_button.clicked.connect(functools.partial(self.goto_prev_change, register))
        next_button.clicked.connect(functools.partial(self.goto_next_change, register))
        label.follow_requested.connect(functools.partial(self.follow_value, line))
        label.jump_requested.connect(self.jump_in_ida_view)
        label.customContextMenuRequested.connect(
            functools.partial(self.show_context_menu, line)
        )

        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(SPACING)
        for child in (line.bar, pin_button, name, prev_button, label, next_button):
            layout.addWidget(child)
        layout.addStretch(1)
        return line

    # layout

    def _chrome_width(self) -> int:
        """The scroll bar and the margins around the lines"""
        margins = self.content_layout.contentsMargins()
        bar = self.scroll.verticalScrollBar().sizeHint().width()
        return bar + margins.left() + margins.right()

    def sizeHint(self) -> QSize:
        """A line and the scroll bar"""
        width = self.metrics.line_width + self._chrome_width()
        return QSize(width, super().sizeHint().height())

    def _fit_words_per_line(self) -> int:
        return self.metrics.words_per_line(self.scroll.width() - self._chrome_width())

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        words_per_line = self._fit_words_per_line()
        if words_per_line != self.words_per_line:
            self._set_words_per_line(words_per_line)
            self._render()

    def _set_words_per_line(self, words_per_line: int) -> None:
        self.words_per_line = words_per_line
        for line in self.lines:
            if line.wide:
                # the layout would squeeze it below the width of its text
                size = line.register.byte_size
                line.label.setFixedWidth(
                    self.metrics.wide_value_width(size, words_per_line)
                )

    def _arrange_lines(self) -> None:
        """The pinned registers in the order they were pinned, then the others"""
        while self.content_layout.takeAt(0) is not None:
            pass

        pinned = self.session.pinned_registers
        by_name = {line.register.name: line for line in self.lines}
        for name in pinned:
            self.content_layout.addWidget(by_name[name].widget)
        self.separator.setVisible(bool(pinned))
        self.content_layout.addWidget(self.separator)
        for line in self.lines:
            if line.register.name not in pinned:
                self.content_layout.addWidget(line.widget)
        self.content_layout.addStretch(1)

    def on_pinned_changed(self) -> None:
        for line in self.lines:
            line.pin_button.setChecked(
                line.register.name in self.session.pinned_registers
            )
        self._arrange_lines()

    # theme

    def on_palette_change(self) -> None:
        super().on_palette_change()
        self.colors = RegisterColors.from_palette(self.palette())
        self._update_pin_colors()
        self._render()

    def _update_pin_colors(self) -> None:
        self.content.setStyleSheet(
            f"QToolButton#pin {{ color: {self.colors.muted.name()}; }}"
            f"QToolButton#pin:checked {{ color: {self.colors.text.name()}; }}"
        )

    # time

    def on_time_update(self) -> None:
        for line in self.lines:
            line.state = read_state(line.register, self.session)
        self._render()

    def _render(self) -> None:
        for line in self.lines:
            state = line.state
            if state is None:
                # before the first `on_time_update`
                continue

            if state.value is None:
                line.label.setText(span("<undefined>", self.colors.muted))
                line.label.setToolTip("")
            else:
                size = line.register.byte_size
                if line.wide:
                    word_size, words_per_line = (
                        self.metrics.pointer_size,
                        self.words_per_line,
                    )
                else:
                    word_size, words_per_line = size, 1
                line.label.setText(
                    value_html(state, size, word_size, words_per_line, self.colors)
                )
                line.label.setToolTip(VALUE_KIND_TOOLTIPS.get(state.value_kind, ""))

            line.label.address = state.value if self.is_address(line) else None
            line.bar.set_color(self.colors.bar[state.write])

    # actions

    def is_address(self, line: RegisterLine) -> bool:
        """Whether the value of the line can be followed: it has the size of a pointer"""
        return (
            line.state is not None
            and line.state.value is not None
            and line.register.byte_size == self.session.pointer_size
        )

    def show_context_menu(self, line: RegisterLine, pos: QPoint) -> None:
        self.show_menu(self.context_menu(line), line.label.mapToGlobal(pos))

    def context_menu(self, line: RegisterLine) -> QMenu:
        menu = QMenu(self)
        value = None if line.state is None else line.state.value

        # the selection, or the compact value without the line breaks of wide registers
        if value is None:
            text = "<undefined>"
        else:
            text = line.label.selectedText() or hex_value(
                value, line.register.byte_size
            )
        self.add_copy_action(menu, "Copy Value", lambda: text)

        if self.is_address(line):
            menu.addSeparator()
            self.add_follow_address_actions(menu, value)
        return menu

    def follow_value(self, line: RegisterLine, address: int) -> None:
        """A function in the IDA view, the rest in the memory view focused last"""
        if line.state is not None and line.state.value_kind == ValueKind.FUNCTION:
            self.jump_in_ida_view(address)
        else:
            self.follow_in_last_memory.emit(address)

    def jump_in_ida_view(self, address: int) -> None:
        ea = self.session.to_idb_addr(address)
        if ea is not None:
            ida_kernwin.jumpto(ea)

    def goto_prev_change(self, register: Register) -> None:
        self.session.goto(register.prev_change(self.session.time))

    def goto_next_change(self, register: Register) -> None:
        self.session.goto(register.next_change(self.session.time))
