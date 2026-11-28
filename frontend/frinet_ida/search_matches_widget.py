from collections.abc import Sequence
from typing import Callable

from .qt.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPoint,
    QSortFilterProxyModel,
    Qt,
)
from .qt.QtGui import QFontMetrics
from .qt.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QPushButton,
    QTableView,
    QVBoxLayout,
)

from frinet import Cancelled, FrinetError, SearchMatch, SearchMatches, Task

from .session import Session
from .tasks import watch
from .utils import format_address, format_ascii, format_bytes
from .widget import (
    MAX_ADDR,
    MAX_MENU_BYTES,
    FrinetWidget,
    monospace_font,
)
from . import theme

DisplayRole = Qt.ItemDataRole.DisplayRole
FontRole = Qt.ItemDataRole.FontRole
TextAlignmentRole = Qt.ItemDataRole.TextAlignmentRole
ToolTipRole = Qt.ItemDataRole.ToolTipRole
# raw value of a cell, what the matches are sorted by
ValueRole = Qt.ItemDataRole.UserRole

# bytes the Context column shows, from the start of the match: what follows a
# short match is usually what identifies it
CONTEXT_BYTES = 24

# of the number columns, combined once instead of at every cell
RIGHT_ALIGNED = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter


class SearchMatchesModel(QAbstractTableModel):
    ADDRESS, MODULE, SIZE, FIRST_TIME, LAST_TIME, CONTEXT = range(6)
    HEADERS = ("Address", "Module", "Size", "First time", "Last time", "Context")

    def __init__(self, session: Session):
        super().__init__()
        self.session = session
        self.matches: Sequence[SearchMatch] = ()
        self._mono = monospace_font()
        # context bytes of a row, read once: the user scrolls over the same rows
        self._bytes_cache: dict[int, list[int | None]] = {}

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.matches)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section: int, orientation, role=DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == DisplayRole:
            return self.HEADERS[section]
        return None

    def set_matches(self, matches: Sequence[SearchMatch]) -> None:
        """Takes what the search found, a match being built when its row is read"""
        self.beginResetModel()
        self.matches = matches
        self._bytes_cache.clear()
        self.endResetModel()

    def data(self, index: QModelIndex, role=DisplayRole):
        if not index.isValid():
            return None
        row, column = index.row(), index.column()
        match = self.matches[row]

        if role == FontRole and column in (self.ADDRESS, self.CONTEXT):
            return self._mono

        if role == TextAlignmentRole and column in (
            self.SIZE,
            self.FIRST_TIME,
            self.LAST_TIME,
        ):
            return RIGHT_ALIGNED

        if role == ToolTipRole and column == self.CONTEXT:
            return self._context(row)

        if role not in (DisplayRole, ValueRole):
            return None
        # ValueRole is what the matches are sorted by: the numbers as numbers,
        # and the row itself for the context, which has no value to order
        raw = role == ValueRole

        match column:
            case self.ADDRESS:
                return match.addr if raw else format_address(match.addr)
            case self.MODULE:
                return self._module(row)
            case self.SIZE:
                return match.size if raw else str(match.size)
            case self.FIRST_TIME:
                return match.first_time if raw else str(match.first_time)
            case self.LAST_TIME:
                return match.last_time if raw else str(match.last_time)
            case self.CONTEXT:
                return row if raw else self._context(row)
        return None

    def _module(self, row: int) -> str:
        match = self.matches[row]
        module = self.session.trace.module_at(match.addr)
        return "" if module is None else f"{module.name}+{match.addr - module.start:#x}"

    def context_bytes(self, row: int) -> list[int | None]:
        """What the Context column shows, read once: rows are scrolled over again"""
        if row not in self._bytes_cache:
            self._bytes_cache[row] = self._read(row, CONTEXT_BYTES)
        return self._bytes_cache[row]

    def match_bytes(self, row: int) -> list[int | None]:
        """Bytes of the match itself, read when an action needs them"""
        return self._read(row, min(self.matches[row].size, MAX_MENU_BYTES))

    def _read(self, row: int, size: int) -> list[int | None]:
        match = self.matches[row]
        state = self.session.trace.at(match.first_time)
        size = min(size, MAX_ADDR - match.addr)
        return state.mem.read_with_unknowns(match.addr, size)

    def _context(self, row: int) -> str:
        data = self.context_bytes(row)
        return f"{''.join(format_ascii(val) for val in data)}  {format_bytes(data)}"


class SearchMatchesWidget(FrinetWidget):
    def __init__(
        self,
        session: Session,
        memory_view_ids: Callable[[], list[int]],
        task: Task[SearchMatches],
        query: str = "",
    ):
        super().__init__(session, memory_view_ids)
        self.query = query
        self.task = task
        self._error: FrinetError | None = None
        self._progress = 0.0
        self._running = True
        self._cancelled = False
        self.model = SearchMatchesModel(session)
        # the view sorts the matches on their raw values, see `ValueRole`
        self.proxy = QSortFilterProxyModel()
        self.proxy.setSortRole(ValueRole)
        self.proxy.setSourceModel(self.model)

        self.setup_ui()

        self.destroyed.connect(lambda *_: task.cancel())

        watch(self, task, self._on_tick, self._on_end)

    def setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        header = QHBoxLayout()
        self.count_label = QLabel(self)
        self.cancel_button = QPushButton("Cancel", self)
        self.cancel_button.clicked.connect(lambda: self.task.cancel())
        header.addWidget(self.count_label)
        header.addWidget(self.cancel_button)
        header.addStretch()
        layout.addLayout(header)

        self.table = QTableView(self)
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        theme.apply_view_palette(self.table)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setSortingEnabled(True)
        self.proxy.setDynamicSortFilter(False)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(
            self.fontMetrics().height() + 6
        )
        header_view = self.table.horizontalHeader()
        header_view.setStretchLastSection(True)
        header_view.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        # a width measured from a few rows: sizing the columns on the content of
        # millions of matches would read the memory of every one of them
        header_view.setResizeContentsPrecision(64)
        layout.addWidget(self.table)

        # only an activated match is followed: selecting one, which a right
        # click does to aim its menu, leaves the trace where the user put it
        self.table.activated.connect(self._show_match)

        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._ctx_menu_handler)

        self._set_column_widths()

    def _set_column_widths(self) -> None:
        digits = QFontMetrics(monospace_font()).horizontalAdvance("0")
        chars = {
            SearchMatchesModel.ADDRESS: 19,
            SearchMatchesModel.MODULE: 18,
            SearchMatchesModel.SIZE: 6,
            SearchMatchesModel.FIRST_TIME: 11,
            SearchMatchesModel.LAST_TIME: 11,
        }
        for column, count in chars.items():
            self.table.setColumnWidth(column, count * digits)

    def _row_at(self, index: QModelIndex) -> int | None:
        return None if not index.isValid() else self.proxy.mapToSource(index).row()

    def _on_tick(self, progress: float) -> None:
        self._progress = progress
        self._update_count()

    def _on_end(self, matches: SearchMatches | None, error: FrinetError | None) -> None:
        self._running = False
        self.cancel_button.hide()
        if isinstance(error, Cancelled):
            self._cancelled = True
        elif error is not None:
            self._error = error
        elif matches is not None:
            self.model.set_matches(matches)
            self.table.sortByColumn(
                SearchMatchesModel.ADDRESS, Qt.SortOrder.AscendingOrder
            )
        self._update_count()

    def _update_count(self) -> None:
        if self._error is not None:
            text = f"Search failed: {self._error}"
        elif self._running:
            text = f"Searching… {self._progress:.0%}"
        elif self._cancelled:
            text = f"Cancelled at {self._progress:.0%}"
        else:
            total = self.model.rowCount()
            text = f"{total:,} match{'' if total == 1 else 'es'}"
            if self.query:
                text += f" for {self.query}"
        self.count_label.setText(text)

    def _show_match(self, index: QModelIndex) -> None:
        """
        Double click or Enter: goes to the time the match appeared and shows it
        in a memory view, opening one when there is none
        """
        row = self._row_at(index)
        if row is None:
            return
        match = self.model.matches[row]
        self.session.goto(match.first_time)
        view_ids = self.memory_view_ids()
        self.follow_in_memory.emit(match.addr, view_ids[0] if view_ids else None)

    # context menu

    def _ctx_menu_handler(self, position: QPoint) -> None:
        index = self.table.indexAt(position)
        if not index.isValid():
            return
        self.table.setCurrentIndex(index)
        viewport = self.table.viewport()
        self.show_menu(self.context_menu(index), viewport.mapToGlobal(position))

    def context_menu(self, index: QModelIndex) -> QMenu:
        menu = QMenu(self)
        row = self._row_at(index)
        if row is None:
            return menu
        match = self.model.matches[row]
        self.add_copy_action(
            menu,
            f"Copy address ({format_address(match.addr)})",
            lambda: hex(match.addr),
        )
        if match.size <= MAX_MENU_BYTES:
            self.add_copy_action(
                menu,
                "Copy bytes (hex)",
                lambda: format_bytes(self.model.match_bytes(row)),
            )
        menu.addSeparator()
        self.add_follow_address_actions(menu, match.addr)
        return menu
