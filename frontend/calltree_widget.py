"""
Call tree window for the frinet IDA plugin.

Loads a .calls.txt file written by trace.py / calltree.py and shows it as a tree.
  * double-click a function / API  -> jump to it in IDA
  * double-click the "Called from" column -> jump to the call instruction
  * if a Frinet DB is open, the trace time is also moved to that call
    (Timeline / Registers / Memory windows follow)
  * "Sync" on: when the trace time changes (timeline, prev/next execution...),
    the function running at that moment is selected in the tree
"""
import bisect
import re
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QCheckBox,
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

LINE_RE = re.compile(r"^line=(\d+)")
EVENT_RE = re.compile(r"^(call|api|ret)\s+(.*?)\s*$")
ROLE_EVENT = Qt.ItemDataRole.UserRole


class CallEvent:
    def __init__(self, line: int, depth: int, kind: str, target: str, site: str):
        self.line = line        # line number in the .tenet file
        self.depth = depth
        self.kind = kind        # call | api | root
        self.target = target    # function / API name or address
        self.site = site        # address of the call instruction
        self.end_line: Optional[int] = None  # line of the matching return
        self.children: list["CallEvent"] = []


def parse_calls_file(path: str) -> CallEvent:
    """Parse a .calls.txt file into a tree of CallEvent (returns the root)."""
    root = CallEvent(0, -1, "root", "trace", "")
    stack = [root]  # stack[d + 1] = open call at depth d

    with open(path, "r", encoding="utf-8", errors="replace") as fd:
        for raw in fd:
            raw = raw.rstrip("\r\n")
            if not raw or raw.startswith("#"):
                continue
            m = LINE_RE.match(raw)
            if not m:
                # header line "   <function>  (traced function)"
                text = raw.strip()
                if text:
                    root.target = text.replace("(traced function)", "").strip()
                continue

            line = int(m.group(1))
            digits = m.group(1)
            body = raw[5 + max(9, len(digits)):]
            indent = len(body) - len(body.lstrip(" "))
            depth = max(0, indent // 4 - 1)
            body = body.strip()

            if "(traced function)" in body:
                root.target = body.replace("(traced function)", "").strip()
                root.line = line
                continue

            em = EVENT_RE.match(body)
            if not em:
                continue
            kind, rest = em.group(1), em.group(2)

            # close calls deeper than this event
            while len(stack) > depth + 1:
                done = stack.pop()
                if done.end_line is None:
                    done.end_line = line

            if kind == "ret":
                continue

            if "   @" in rest:
                target, site = rest.rsplit("   @", 1)
            else:
                target, site = rest, ""
            ev = CallEvent(line, depth, kind, target.strip(), site.strip())
            stack[-1].children.append(ev)
            if kind == "call":
                stack.append(ev)
    return root


class CallTreeWidget(QWidget):
    def __init__(self, ctx, navigate, path: str):
        super().__init__()
        self.ctx = ctx
        self.navigate = navigate  # callable(ea)
        self.path = path
        self.root = parse_calls_file(path)
        self._items = {}        # id(CallEvent) -> QTreeWidgetItem
        self._marked = []       # items highlighted as the current call path
        self._syncing = False
        self._setup_ui()
        self._populate()
        if self.ctx is not None:
            self.ctx.register_time_observer(self)
            ctx, me = self.ctx, self
            # plain closure: a bound method of a dying widget is not called by Qt
            self.destroyed.connect(lambda *_: ctx.unregister_time_observer(me))
            self.on_time_update()

    # ---------- UI ----------
    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)

        bar = QHBoxLayout()
        self.filter_edit = QLineEdit(self)
        self.filter_edit.setPlaceholderText("Filter (e.g. WriteFile, sub_14000E424)...")
        self.filter_edit.textChanged.connect(self._apply_filter)
        self.show_api = QCheckBox("APIs", self)
        self.show_api.setChecked(True)
        self.show_api.toggled.connect(self._populate)
        expand = QPushButton("Expand", self)
        expand.clicked.connect(lambda: self.tree.expandAll())
        collapse = QPushButton("Collapse", self)
        collapse.clicked.connect(lambda: self.tree.collapseAll())
        self.sync = QCheckBox("Sync", self)
        self.sync.setToolTip("Follow the trace time: select the function running at the current time")
        self.sync.setChecked(True)
        self.sync.toggled.connect(lambda on: on and self.on_time_update())
        bar.addWidget(self.filter_edit)
        bar.addWidget(self.sync)
        bar.addWidget(self.show_api)
        bar.addWidget(expand)
        bar.addWidget(collapse)
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

    def _populate(self) -> None:
        self.tree.clear()
        self._items = {}
        self._marked = []
        with_api = self.show_api.isChecked()

        def add(parent_item, ev: CallEvent):
            for child in ev.children:
                if child.kind == "api" and not with_api:
                    continue
                label = child.target if child.kind == "call" else f"[API] {child.target}"
                it = QTreeWidgetItem(
                    parent_item,
                    [
                        label,
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

        top = QTreeWidgetItem(self.tree, [self.root.target, "", str(self.root.line or ""), ""])
        top.setData(0, ROLE_EVENT, self.root)
        self._items[id(self.root)] = top
        add(top, self.root)
        self.tree.expandToDepth(1)
        self._apply_filter(self.filter_edit.text())
        if self.ctx is not None:
            self.on_time_update()

    # ---------- timeline synchronisation ----------
    @staticmethod
    def _line_to_time(line: int) -> int:
        return line - 1  # .tenet line n  ~ frinet time n-1

    def _path_at(self, t: int) -> list:
        """Chain of events (root .. deepest) active at trace time t."""
        path = [self.root]
        node = self.root
        while True:
            kids = node.children
            if not kids:
                break
            starts = [self._line_to_time(k.line) for k in kids]
            i = bisect.bisect_right(starts, t) - 1
            nxt = None
            while i >= 0:
                k = kids[i]
                start = starts[i]
                if k.kind == "api":
                    if start == t:  # exactly on the API call
                        nxt = k
                        break
                    i -= 1
                    continue
                end = self._line_to_time(k.end_line) if k.end_line is not None else float("inf")
                if start <= t <= end:
                    nxt = k
                break
            if nxt is None:
                break
            path.append(nxt)
            if nxt.kind == "api":
                break
            node = nxt
        return path

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
        self._syncing = True
        self.tree.setCurrentItem(target)
        self.tree.scrollToItem(target)
        self._syncing = False

    def _apply_filter(self, text: str) -> None:
        text = text.strip().lower()

        def visit(item: QTreeWidgetItem) -> bool:
            match = not text or text in item.text(0).lower() or text in item.text(1).lower()
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

    # ---------- navigation ----------
    def _goto_target(self, ev: CallEvent) -> None:
        ea = resolve_name(ev.target, self.ctx)
        if ea is not None:
            self.navigate(ea)
        else:
            print(f"[frinet] cannot resolve '{ev.target}' in this database")

    def _goto_site(self, ev: CallEvent) -> None:
        ea = resolve_addr(ev.site, self.ctx) if ev.site else None
        if ev.line:
            self._set_trace_time(ev.line, ea)
        if ea is not None:
            self.navigate(ea)  # after set_time, so IDA ends up here

    def _set_trace_time(self, line: int, ea: Optional[int]) -> None:
        """Move frinet's trace time to the instruction written on <line> of the .tenet."""
        ctx = self.ctx
        if ctx is None or not ctx.has_db():
            return
        db = ctx.db
        candidates = [line - 1, line, line - 2, line + 1, line - 3]
        best = line - 1
        if ea is not None:
            import ida_nalt
            wanted = {ea, ea - ida_nalt.get_imagebase()}
            for t in candidates:
                pc = db.pc_at(db.clamp_time(t))
                if pc is not None and db.unslide(pc) in wanted:
                    best = t
                    break
        ctx.set_time(best)


# ---------- name / address resolution in IDA ----------
def resolve_addr(text: str, ctx=None) -> Optional[int]:
    """'14000E629' (IDA address) or '0x7ff7...' (runtime address) -> IDA ea."""
    import ida_bytes
    import ida_nalt

    text = text.strip()
    if not text:
        return None
    try:
        val = int(text, 16)
    except ValueError:
        return resolve_name(text, ctx)
    if ida_bytes.is_mapped(val):
        return val
    if ctx is not None and ctx.has_db():  # runtime address -> IDA
        off = ctx.db.unslide(val)
        if off is not None:
            for ea in (off, off + ida_nalt.get_imagebase()):
                if ida_bytes.is_mapped(ea):
                    return ea
    return None


def resolve_name(text: str, ctx=None) -> Optional[int]:
    """sub_14000E424 / KERNEL32!CreateFileW / mod!func / mod+0x1234 -> IDA ea."""
    import ida_bytes
    import ida_idaapi
    import ida_name
    import ida_nalt

    text = text.strip()
    if text.startswith("[API] "):
        text = text[6:]

    m = re.match(r"^sub_([0-9A-Fa-f]+)$", text)
    if m:
        return int(m.group(1), 16)

    m = re.match(r"^(.+?)\+0x([0-9A-Fa-f]+)$", text)  # module+offset
    if m:
        off = int(m.group(2), 16)
        for ea in (ida_nalt.get_imagebase() + off, off):
            if ida_bytes.is_mapped(ea):
                return ea
        return None

    if re.match(r"^(0x)?[0-9A-Fa-f]+$", text):
        return resolve_addr(text, ctx)

    func = text.split("!", 1)[1] if "!" in text else text
    func = re.sub(r"\+0x[0-9A-Fa-f]+$", "", func)
    for cand in (func, "__imp_" + func, "_" + func):  # function, IAT entry
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, cand)
        if ea != ida_idaapi.BADADDR:
            return ea
    if func.startswith("Ordinal_"):
        for cand in (func, "__imp_" + func):
            ea = ida_name.get_name_ea(ida_idaapi.BADADDR, cand)
            if ea != ida_idaapi.BADADDR:
                return ea
    return None
