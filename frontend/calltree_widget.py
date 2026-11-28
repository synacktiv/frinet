"""
Call tree window for the frinet IDA plugin.

Shows a .calls.txt call list (see calls_model.py) as a tree.
  * double-click a function / API  -> jump to it in IDA
  * double-click the "Called from" column -> jump to the call instruction and,
    if a Frinet DB is open, move the trace time to that call
  * Names: show addresses (sub_14000E424) or real names (current IDA names)
  * Sync: follows the trace time and highlights the active call chain
  * Graph / Story: open the other views of the same call list
"""
from typing import Callable, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QMenu,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from calls_model import (  # noqa: F401  (re-exported for older imports)
    NAMES_ADDRESS,
    NAMES_REAL,
    CallEvent,
    CallModel,
    parse_calls_file,
    resolve_addr,
    resolve_name,
)

ROLE_EVENT = Qt.ItemDataRole.UserRole


class CallTreeWidget(QWidget):
    def __init__(
        self,
        ctx,
        navigate: Callable[[int], None],
        model,
        open_graph: Optional[Callable] = None,
        open_story: Optional[Callable] = None,
    ):
        super().__init__()
        if isinstance(model, str):  # backward compatible: a path
            model = CallModel(model, ctx)
        self.ctx = ctx
        self.navigate = navigate
        self.model = model
        self.root = model.root
        self._open_graph = open_graph
        self._open_story = open_story
        self._items = {}        # id(CallEvent) -> QTreeWidgetItem
        self._marked = []       # items highlighted as the current call path
        self._setup_ui()
        self._populate()
        self.model.add_listener(self._refresh_names)
        if self.ctx is not None:
            self.ctx.register_time_observer(self)
            ctx_, me, model_ = self.ctx, self, self.model
            # plain closure: a bound method of a dying widget is not called by Qt
            self.destroyed.connect(
                lambda *_: (ctx_.unregister_time_observer(me), model_.remove_listener(me._refresh_names))
            )
            self.on_time_update()

    # ---------- UI ----------
    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)

        bar = QHBoxLayout()
        self.filter_edit = QLineEdit(self)
        self.filter_edit.setPlaceholderText("Filter (e.g. WriteFile)...")
        self.filter_edit.textChanged.connect(self._apply_filter)

        self.names = QComboBox(self)
        self.names.addItem("Real names", NAMES_REAL)
        self.names.addItem("Addresses", NAMES_ADDRESS)
        self.names.setToolTip(
            "Real names: current IDA names (PDB symbols, your renames)\n"
            "Addresses: sub_<address> as in the call list"
        )
        self.names.setCurrentIndex(0 if self.model.name_mode == NAMES_REAL else 1)
        self.names.currentIndexChanged.connect(
            lambda _i: self.model.set_name_mode(self.names.currentData())
        )

        self.sync = QCheckBox("Sync", self)
        self.sync.setToolTip("Follow the trace time: select the function running at the current time")
        self.sync.setChecked(True)
        self.sync.toggled.connect(lambda on: on and self.on_time_update())
        self.show_api = QCheckBox("APIs", self)
        self.show_api.setChecked(True)
        self.show_api.toggled.connect(lambda _on: self._populate())

        expand = QPushButton("Expand", self)
        expand.clicked.connect(lambda: self.tree.expandAll())
        collapse = QPushButton("Collapse", self)
        collapse.clicked.connect(lambda: self.tree.collapseAll())

        bar.addWidget(self.filter_edit)
        bar.addWidget(self.names)
        bar.addWidget(self.sync)
        bar.addWidget(self.show_api)
        bar.addWidget(expand)
        bar.addWidget(collapse)
        if self._open_graph is not None:
            b = QPushButton("Graph", self)
            b.setToolTip("Open the call graph / flame chart of this call list")
            b.clicked.connect(lambda: self._open_graph(self.model))
            bar.addWidget(b)
        if self._open_story is not None:
            b = QPushButton("Story", self)
            b.setToolTip("Open the narrative of this trace, with links to points in time")
            b.clicked.connect(lambda: self._open_story(self.model))
            bar.addWidget(b)
        layout.addLayout(bar)

        self.tree = QTreeWidget(self)
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Function", "Called from", "Line", "Return line"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self.tree.setColumnWidth(0, 320)
        self.tree.setUniformRowHeights(True)
        self.tree.itemDoubleClicked.connect(self._on_double_click)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.tree)

    def _label(self, ev: CallEvent) -> str:
        name = self.model.display_name(ev)
        return f"[API] {name}" if ev.kind == "api" else name

    def _populate(self) -> None:
        self.tree.clear()
        self._items = {}
        self._marked = []
        with_api = self.show_api.isChecked()

        def add(parent_item, ev: CallEvent):
            for child in ev.children:
                if child.kind == "api" and not with_api:
                    continue
                it = QTreeWidgetItem(
                    parent_item,
                    [
                        self._label(child),
                        child.site,
                        str(child.line),
                        "" if child.end_line is None else str(child.end_line),
                    ],
                )
                it.setData(0, ROLE_EVENT, child)
                self._items[id(child)] = it
                if child.kind == "api":
                    it.setForeground(0, Qt.GlobalColor.darkMagenta)
                add(it, child)

        top = QTreeWidgetItem(
            self.tree, [self.model.name_of(self.root.target), "", str(self.root.line or ""), ""]
        )
        top.setData(0, ROLE_EVENT, self.root)
        self._items[id(self.root)] = top
        add(top, self.root)
        self.tree.expandToDepth(1)
        self._apply_filter(self.filter_edit.text())
        if self.ctx is not None:
            self.on_time_update()

    def _refresh_names(self) -> None:
        """Names changed (mode switch or IDA rename): update labels in place."""
        for key, it in self._items.items():
            ev = it.data(0, ROLE_EVENT)
            if ev is None:
                continue
            it.setText(0, self.model.name_of(ev.target) if ev.kind == "root" else self._label(ev))
        self._apply_filter(self.filter_edit.text())

    def _apply_filter(self, text: str) -> None:
        text = text.strip().lower()

        def visit(item: QTreeWidgetItem) -> bool:
            ev = item.data(0, ROLE_EVENT)
            raw = ev.target.lower() if ev is not None else ""
            match = (
                not text
                or text in item.text(0).lower()
                or text in item.text(1).lower()
                or text in raw
            )
            child_match = False
            for i in range(item.childCount()):
                if visit(item.child(i)):
                    child_match = True
            item.setHidden(not (match or child_match))
            if text and child_match:
                item.setExpanded(True)
            return match or child_match

        for i in range(self.tree.topLevelItemCount()):
            visit(self.tree.topLevelItem(i))

    # ---------- timeline synchronisation ----------
    def _path_at(self, t: int) -> list:
        return self.model.active_path(t)

    def on_time_update(self) -> None:
        if not self.sync.isChecked() or self.ctx is None or not self.ctx.has_db():
            return
        path = self._path_at(self.ctx.db.time)

        for it in self._marked:  # clear previous highlight
            f = it.font(0)
            f.setBold(False)
            it.setFont(0, f)
            it.setBackground(0, QBrush())
        self._marked = []

        target = None
        for ev in path:
            it = self._items.get(id(ev))
            if it is None or it.isHidden():
                continue  # filtered out / API hidden: keep the parent
            f = it.font(0)
            f.setBold(True)
            it.setFont(0, f)
            self._marked.append(it)
            target = it
        if target is None:
            return
        target.setBackground(0, QBrush(QColor(255, 230, 150)))
        p = target.parent()
        while p is not None:
            p.setExpanded(True)
            p = p.parent()
        self.tree.setCurrentItem(target)
        self.tree.scrollToItem(target)

    # ---------- interaction ----------
    def _context_menu(self, pos) -> None:
        item = self.tree.itemAt(pos)
        if item is None:
            return
        ev = item.data(0, ROLE_EVENT)
        menu = QMenu(self)
        a_func = menu.addAction("Go to function")
        a_site = menu.addAction("Go to call site (and trace time)")
        a_ret = menu.addAction("Go to return (trace time)")
        a_ret.setEnabled(ev is not None and ev.end_line is not None)
        chosen = menu.exec(self.tree.viewport().mapToGlobal(pos))
        if chosen == a_func:
            self._goto_target(ev)
        elif chosen == a_site:
            self._goto_site(ev)
        elif chosen == a_ret and ev.end_line is not None:
            self._set_trace_time(ev.end_line, None)

    def _on_double_click(self, item: QTreeWidgetItem, column: int) -> None:
        ev = item.data(0, ROLE_EVENT)
        if ev is None:
            return
        if column == 1:
            self._goto_site(ev)
        else:
            self._goto_target(ev)

    def _goto_target(self, ev: CallEvent) -> None:
        goto_target(self.model, ev, self.navigate)

    def _goto_site(self, ev: CallEvent) -> None:
        goto_site(self.model, ev, self.navigate)

    def _set_trace_time(self, line: int, ea: Optional[int]) -> None:
        set_trace_time_at_line(self.ctx, line, ea)


# ---------- navigation helpers shared by all call-list views ----------
def goto_target(model, ev: CallEvent, navigate) -> None:
    ea = model.target_ea(ev)
    if ea is not None:
        navigate(ea)
    else:
        print(f"[frinet] cannot resolve '{ev.target}' in this database")


def goto_site(model, ev: CallEvent, navigate) -> None:
    ea = model.site_ea(ev)
    if ev.line:
        set_trace_time_at_line(model.ctx, ev.line, ea)
    if ea is not None:
        navigate(ea)  # after set_time, so IDA ends up here


def set_trace_time_at_line(ctx, line: int, ea: Optional[int]) -> None:
    """Move frinet's trace time to the instruction written on <line> of the .tenet."""
    if ctx is None or not ctx.has_db():
        return
    db = ctx.db
    best = line - 1
    if ea is not None:
        import ida_nalt

        wanted = {ea, ea - ida_nalt.get_imagebase()}
        for t in (line - 1, line, line - 2, line + 1, line - 3):
            pc = db.pc_at(db.clamp_time(t))
            if pc is not None and db.unslide(pc) in wanted:
                best = t
                break
    ctx.set_time(best)
