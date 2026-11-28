from bisect import bisect_right
from dataclasses import dataclass
from typing import Callable

from .qt.QtCore import QAbstractTableModel, QModelIndex, QPoint, QSize, Qt
from .qt.QtGui import QColor, QResizeEvent
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

import ida_funcs
import ida_idp
from frinet import Calltree, Span

from .program_info import build_calltree
from .session import Session
from .utils import format_address
from .widget import FrinetWidget, monospace_font, polished_metrics
from . import theme

DisplayRole = Qt.ItemDataRole.DisplayRole
ForegroundRole = Qt.ItemDataRole.ForegroundRole

NORMAL, EXTERNAL, THUNK = range(3)

WIDTH_DIGITS = 30

INDENT = "  "


@dataclass(frozen=True)
class Hole:
    """The descendants of a folded span, the spans `start` to `end` excluded"""

    start: int
    end: int
    #: Spans hidden by the holes before this one
    hidden_before: int

    @property
    def hidden_through(self) -> int:
        return self.hidden_before + self.end - self.start

    @property
    def row_after(self) -> int:
        """Row of the span `end`, the first one shown after the hole"""
        return self.start - self.hidden_before


class CalltreeModel(QAbstractTableModel):
    """
    One row per span, in the order of the calltree, which keeps the descendants
    of a span right after it: a folded span hides them as one hole, and a row
    is its span less the spans hidden before it
    """

    def __init__(self, session: Session, tree: Calltree):
        super().__init__()
        self.session = session
        self.tree = tree
        self.folded: set[int] = set()
        self._holes: list[Hole] = []
        self._names: dict[int, str] = {}
        self._kinds: dict[int, int] = {}
        self._colors: dict[int, QColor] = {}

    # rows

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else self._row_count(self._holes)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 1

    def span(self, row: int) -> Span:
        hole = self._hole_before(self._holes, row, lambda hole: hole.row_after)
        return self.tree.span(row + (hole.hidden_through if hole else 0))

    def row_of(self, span: int) -> int:
        """Row of `span`, or of the folded span hiding it"""
        hole = self._hole_before(self._holes, span, lambda hole: hole.start)
        if hole is None:
            return span
        if span < hole.end:
            return hole.start - 1 - hole.hidden_before
        return span - hole.hidden_through

    # folding

    def toggle(self, row: int) -> None:
        span = self.span(row)
        if not span.has_children:
            return

        folded = self.folded ^ {span.index}
        holes = self._holes_of(folded)
        shown, before = self._row_count(holes), self.rowCount()
        if shown < before:
            self.beginRemoveRows(QModelIndex(), row + 1, row + before - shown)
        else:
            self.beginInsertRows(QModelIndex(), row + 1, row + shown - before)
        self.folded, self._holes = folded, holes
        if shown < before:
            self.endRemoveRows()
        else:
            self.endInsertRows()

        index = self.index(row, 0)
        self.dataChanged.emit(index, index)

    def expand_all(self) -> None:
        self.beginResetModel()
        self.folded, self._holes = set(), []
        self.endResetModel()

    def _holes_of(self, folded: set[int]) -> list[Hole]:
        """The outermost folded spans make the holes, the others stay folded inside"""
        holes: list[Hole] = []
        end = hidden = 0
        for span in sorted(folded):
            if span < end:
                continue
            end = self.tree.span(span).subtree_end
            holes.append(Hole(span + 1, end, hidden))
            hidden = holes[-1].hidden_through
        return holes

    def _row_count(self, holes: list[Hole]) -> int:
        return len(self.tree) - (holes[-1].hidden_through if holes else 0)

    @staticmethod
    def _hole_before(
        holes: list[Hole], value: int, key: Callable[[Hole], int]
    ) -> Hole | None:
        position = bisect_right(holes, value, key=key)
        return holes[position - 1] if position else None

    # content

    def data(self, index: QModelIndex, role=DisplayRole):
        if not index.isValid():
            return None

        if role == ForegroundRole:
            return self._colors.get(self._kind(self.span(index.row()).entrypoint))

        if role == DisplayRole:
            span = self.span(index.row())
            return INDENT * span.depth + self._glyph(span) + self._name(span.entrypoint)
        return None

    def _glyph(self, span: Span) -> str:
        if not span.has_children:
            return INDENT
        return "▸ " if span.index in self.folded else "▾ "

    def set_colors(self) -> None:
        accents = theme.accents()
        self._colors = {EXTERNAL: accents.external, THUNK: accents.thunk}

    def _name(self, entrypoint: int) -> str:
        if entrypoint not in self._names:
            self._names[entrypoint] = self._resolve_name(entrypoint)
        return self._names[entrypoint]

    def _resolve_name(self, entrypoint: int) -> str:
        ea = self.session.to_idb_addr(entrypoint)
        if ea is None:
            module = self.session.trace.module_at(entrypoint)
            if module is None:
                return format_address(entrypoint)
            offset = entrypoint - module.start
            return module.name if offset == 0 else f"{module.name}+{offset:#x}"
        return ida_funcs.get_func_name(ea) or format_address(entrypoint)

    def _kind(self, entrypoint: int) -> int:
        if entrypoint not in self._kinds:
            self._kinds[entrypoint] = self._resolve_kind(entrypoint)
        return self._kinds[entrypoint]

    def _resolve_kind(self, entrypoint: int) -> int:
        ea = self.session.to_idb_addr(entrypoint)
        if ea is None:
            return EXTERNAL
        func = ida_funcs.get_func(ea)
        if func is not None and func.flags & ida_funcs.FUNC_THUNK:
            return THUNK
        return NORMAL

    def invalidate_labels(self) -> None:
        """Forget the names and the kinds resolved from the IDB"""
        self._names.clear()
        self._kinds.clear()


class CalltreeIdbHooks(ida_idp.IDB_Hooks):
    def __init__(self, widget: "CalltreeWidget"):
        super().__init__()
        self.widget = widget

    def _labels(self, *args) -> int:
        self.widget.refresh_labels()
        return 0

    def _stale(self, *args) -> int:
        self.widget.mark_stale()
        return 0

    renamed = _labels
    func_updated = _labels
    thunk_func_created = _labels

    func_added = _stale
    deleting_func = _stale
    set_func_start = _stale
    set_func_end = _stale
    func_tail_appended = _stale
    func_tail_deleted = _stale


class CalltreeWidget(FrinetWidget):
    model: CalltreeModel | None = None
    stale: bool = False
    _width_hint: int

    def __init__(self, session: Session, memory_view_ids: Callable[[], list[int]]):
        super().__init__(session, memory_view_ids)
        self.setup_ui()

        session.calltree_changed.connect(self.on_calltree_changed)

        self.hooks = CalltreeIdbHooks(self)
        self.hooks.hook()
        self.destroyed.connect(lambda *_: self.hooks.unhook())

        if session.calltree is not None:
            self.on_calltree_changed()

    def setup_ui(self) -> None:
        mono = monospace_font()
        metrics = polished_metrics(mono)
        self._width_hint = metrics.horizontalAdvance("0") * WIDTH_DIGITS

        layout = QVBoxLayout(self)
        layout.setSpacing(4)

        header = QHBoxLayout()
        self.status_label = QLabel(self)
        self.build_button = QPushButton("Build call tree", self)
        self.build_button.clicked.connect(lambda: self.build())
        header.addWidget(self.status_label)
        header.addWidget(self.build_button)
        header.addStretch()
        layout.addLayout(header)

        self.view = QTableView(self)
        self.view.setFont(mono)
        self.view.setShowGrid(False)
        self.view.setWordWrap(False)
        self.view.horizontalHeader().hide()
        self.view.horizontalHeader().setStretchLastSection(False)
        self.view.verticalHeader().hide()
        self.view.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.view.verticalHeader().setMinimumSectionSize(metrics.height())
        self.view.verticalHeader().setDefaultSectionSize(metrics.height() + 2)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.view.setAlternatingRowColors(True)
        self.view.setTextElideMode(Qt.TextElideMode.ElideNone)
        self.view.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        layout.addWidget(self.view)

        self.view.verticalScrollBar().valueChanged.connect(self._fit_column)

        self.view.clicked.connect(self._goto_span)
        self.view.activated.connect(self._goto_span)
        self.view.doubleClicked.connect(self._toggle)

        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self._ctx_menu_handler)

        theme.apply_view_palette(self.view)
        self._update_status()

    def sizeHint(self) -> QSize:
        return QSize(self._width_hint, super().sizeHint().height())

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        if self.model is not None:
            self._fit_column()

    def _fit_column(self, *_) -> None:
        """Width of the column: the widest row in view, and at least the viewport"""
        width = max(self.view.sizeHintForColumn(0), self.view.viewport().width())
        if width != self.view.columnWidth(0):
            self.view.setColumnWidth(0, width)

    def on_palette_change(self) -> None:
        if self.model is not None:
            self.model.set_colors()
            self.view.viewport().update()

    def _trace_steps(self) -> int:
        return len(self.session.trace.times)

    def build(self) -> None:
        if self.session.calltree is None or self.stale:
            if build_calltree(self.session) is not None:
                self.stale = False
        self._update_status()

    def refresh_labels(self) -> None:
        if self.model is not None:
            self.model.invalidate_labels()
            self.view.viewport().update()

    def mark_stale(self) -> None:
        if self.stale or self.session.calltree is None:
            return
        self.stale = True
        self._update_status()

    def on_calltree_changed(self) -> None:
        tree = self.session.calltree
        if tree is None:
            return
        self.stale = False
        self.model = CalltreeModel(self.session, tree)
        self.model.set_colors()
        self.view.setModel(self.model)
        self._update_status()
        self.on_time_update()

    def _update_status(self) -> None:
        tree = self.session.calltree
        stale = self.stale and tree is not None

        self.build_button.setVisible(tree is None or stale)
        self.build_button.setText("Rebuild" if stale else "Build call tree")
        self.view.setVisible(tree is not None)

        if tree is None:
            self.status_label.setText(f"{self._trace_steps():,} steps to walk")
        elif stale:
            self.status_label.setText("The functions of the IDB changed")
        elif tree.complete:
            self.status_label.clear()
        else:
            self.status_label.setText("Stopped on the span limit")
        self.status_label.setVisible(bool(self.status_label.text()))

    def on_time_update(self) -> None:
        tree = self.session.calltree
        if tree is None or self.model is None:
            return

        span = tree.span_at(self.session.time)
        if span is None:
            self.view.setCurrentIndex(QModelIndex())
        else:
            index = self.model.index(self.model.row_of(span), 0)
            self.view.setCurrentIndex(index)
            self.view.scrollTo(index)
        self._fit_column()

    def _goto_span(self, index: QModelIndex) -> None:
        if self.model is not None:
            self.session.goto(self.model.span(index.row()).time_range[0])

    def _toggle(self, index: QModelIndex) -> None:
        if self.model is not None:
            self.model.toggle(index.row())
            self.on_time_update()

    def _expand_all(self) -> None:
        if self.model is not None:
            self.model.expand_all()
            self.on_time_update()

    def _ctx_menu_handler(self, position: QPoint) -> None:
        index = self.view.indexAt(position)
        if not index.isValid():
            return
        self.view.setCurrentIndex(index)
        viewport = self.view.viewport()
        self.show_menu(self.context_menu(index), viewport.mapToGlobal(position))

    def context_menu(self, index: QModelIndex) -> QMenu:
        menu = QMenu(self)
        if self.model is None:
            return menu

        span = self.model.span(index.row())
        time_min, time_max = span.time_range
        self.add_action(menu, "Go to the start", lambda: self.session.goto(time_min))
        self.add_action(menu, "Go to the end", lambda: self.session.goto(time_max))
        menu.addSeparator()
        if span.has_children:
            folded = span.index in self.model.folded
            self.add_action(
                menu, "Expand" if folded else "Collapse", lambda: self._toggle(index)
            )
        self.add_action(menu, "Expand all", self._expand_all)
        return menu
