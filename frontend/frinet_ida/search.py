"""What to look for in memory, and the dialog that asks for it"""

from dataclasses import dataclass
from enum import Enum

from .qt.QtCore import Qt
from .qt.QtGui import QPalette
from .qt.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QVBoxLayout,
)

from frinet import Task, Trace, validate_regex

from .utils import bytes_pattern, format_bytes
from .widget import monospace_font
from . import theme


class SearchMode(Enum):
    """How the text of a query is read"""

    TEXT = "Text"
    HEX = "Hex"
    REGEX = "Regex"


# of the line edit, an example of what the mode accepts
PLACEHOLDERS = {
    SearchMode.TEXT: "HTTP/1.1",
    SearchMode.HEX: "48 54 ?? 50",
    SearchMode.REGEX: "GET /[a-z]+",
}


def parse_hex_bytes(text: str) -> list[int | None]:
    """
    Bytes of a hex string, None for the `??` of any byte: "48 54 ?? 50",
    "4854??50" and "0x48, 0x54" are the same three bytes.

    Raises ValueError for anything else.
    """
    digits = "".join(
        token[2:] if token[:2].lower() == "0x" else token
        for token in text.replace(",", " ").split()
    )

    if not digits:
        raise ValueError("enter the bytes to search")
    if len(digits) % 2:
        raise ValueError(f"{len(digits)} hex digits: a byte takes two of them")

    data: list[int | None] = []
    for idx in range(0, len(digits), 2):
        pair = digits[idx : idx + 2]
        if pair == "??":
            data.append(None)
            continue
        try:
            data.append(int(pair, 16))
        except ValueError:
            raise ValueError(f"'{pair}' is not a hex byte") from None
    return data


@dataclass(frozen=True)
class SearchQuery:
    """A memory search, as the user typed it"""

    mode: SearchMode
    text: str

    @property
    def label(self) -> str:
        """Query and its mode, for a window title"""
        return f"{self.mode.value.lower()} {self.text}"

    def preview(self) -> str:
        """What the search looks for, raises ValueError if the query is invalid"""
        if not self.text:
            raise ValueError("enter the bytes to search")

        if self.mode is SearchMode.REGEX:
            # the engine reads the pattern without searching it
            validate_regex(self.text)
            return "regex over every byte written in the trace"

        data = self._data()
        if all(val is None for val in data):
            raise ValueError("every byte is ??: the search would match anywhere")
        unknown = " (?? matches any byte)" if any(val is None for val in data) else ""
        plural = "" if len(data) == 1 else "s"
        return f"{len(data)} byte{plural}: {format_bytes(data)}{unknown}"

    def start(self, trace: Trace) -> Task:
        """Starts the search on its own thread, raising ValueError for an invalid query"""
        self.preview()  # the query is read the same way, and refused the same way

        if self.mode is SearchMode.REGEX:
            return trace.search_regex(self.text)

        data = self._data()
        if any(val is None for val in data):
            # an unknown byte matches any byte, like a selection of the memory view
            return trace.search_regex(bytes_pattern(data))
        return trace.search(bytes(data))  # type: ignore[arg-type]

    def _data(self) -> list[int | None]:
        """Bytes searched by a text or hex query"""
        if self.mode is SearchMode.HEX:
            return parse_hex_bytes(self.text)
        return list(self.text.encode())


class SearchDialog(QDialog):
    """
    Asks for a query, checking it as it is typed: the Search button is only
    enabled for a query that can be read, so the search never refuses one.
    """

    def __init__(self, parent=None, query: SearchQuery | None = None):
        super().__init__(parent)
        self.setWindowTitle("Search memory")
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)

        query_layout = QHBoxLayout()
        self.mode_box = QComboBox(self)
        for mode in SearchMode:
            self.mode_box.addItem(mode.value, mode)
        self.text_edit = QLineEdit(self)
        self.text_edit.setFont(monospace_font())
        query_layout.addWidget(self.mode_box)
        query_layout.addWidget(self.text_edit, 1)
        layout.addLayout(query_layout)

        self.status_label = QLabel(self)
        # the hex bytes of a preview and the caret of a regex error are aligned
        self.status_label.setFont(monospace_font())
        self.status_label.setWordWrap(True)
        # the dialog keeps its height when the message spans two lines
        self.status_label.setMinimumHeight(2 * self.fontMetrics().height())
        self.status_label.setAlignment(
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
        )
        layout.addWidget(self.status_label)

        # added one by one: combining the standard buttons with | goes through
        # an IDA shim that only works when PyQt5 is imported
        self.buttons = QDialogButtonBox(self)
        self.search_button = self.buttons.addButton(
            "Search", QDialogButtonBox.ButtonRole.AcceptRole
        )
        self.buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.search_button.setDefault(True)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)

        if query is not None:
            self.mode_box.setCurrentIndex(self.mode_box.findData(query.mode))
            self.text_edit.setText(query.text)
        self.text_edit.setFocus()
        self.text_edit.selectAll()

        self.mode_box.currentIndexChanged.connect(self._on_query_changed)
        self.text_edit.textChanged.connect(self._on_query_changed)
        self._on_query_changed()

    def query(self) -> SearchQuery:
        return SearchQuery(self.mode_box.currentData(), self.text_edit.text())

    def _on_query_changed(self) -> None:
        query = self.query()
        self.text_edit.setPlaceholderText(PLACEHOLDERS[query.mode])
        try:
            self._set_status(query.preview(), is_error=False)
            self.search_button.setEnabled(True)
        except ValueError as err:
            # typing a byte at a time goes through invalid queries: an error is
            # only worth showing once there is something to fix
            self._set_status(str(err), is_error=bool(query.text))
            self.search_button.setEnabled(False)

    def _set_status(self, message: str, is_error: bool) -> None:
        palette = self.palette()
        background = palette.color(QPalette.ColorRole.Window)
        if is_error:
            color = theme.accents().error
        else:
            color = theme.muted(
                background, palette.color(QPalette.ColorRole.WindowText)
            )
        self.status_label.setStyleSheet(f"color: {color.name()};")
        self.status_label.setText(message)
