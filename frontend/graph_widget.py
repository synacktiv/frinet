"""
Graph window: how execution moves between functions, synchronized with the timeline.

Two tabs over the same call list (calls_model.CallModel):

  Timeline (flame chart)
    x = trace time, one bar per call from its call to its return, y = call depth.
    Red line = current trace time. Wheel = zoom, drag = pan, click = move the
    trace time there, double-click a bar = go to that call (time + IDA).

  Call graph
    One box per function, arrows = calls (with counts). The chain of calls
    active at the current time is highlighted. Click a box = jump to the next
    call of that function after the current time, double-click = go to the
    function in IDA. Wheel = zoom, drag = pan.
"""
import bisect
import zlib
from typing import Callable, Optional

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QFontMetrics, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QCheckBox,
    QGraphicsItem,
    QGraphicsPathItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsSimpleTextItem,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from calltree_widget import goto_site, goto_target, set_trace_time_at_line
from calls_model import CallEvent, CallModel

ROW_H = 20
AXIS_H = 20
HIGHLIGHT = QColor(255, 210, 80)
CURSOR = QColor(220, 0, 0)


def color_for(key: str, api: bool = False) -> QColor:
    h = zlib.crc32(key.encode()) % 360
    c = QColor()
    if api:
        c.setHsv(300, 90, 215)  # APIs: light magenta
    else:
        c.setHsv(h, 70, 235)
    return c


# =====================================================================
# Flame chart over time
# =====================================================================
class FlameChart(QWidget):
    def __init__(self, owner: "GraphWidget"):
        super().__init__()
        self.owner = owner
        self.model: CallModel = owner.model
        self.setMouseTracking(True)
        self.setMinimumHeight(AXIS_H + ROW_H * 4)
        self.t0, self.t1 = self.model.time_range
        self.t1 = max(self.t1, self.t0 + 1)
        self._drag_x = None
        self._dragged = False
        self._build()

    def _build(self) -> None:
        """Bars per depth, sorted by start (bars at one depth never overlap)."""
        with_api = self.owner.show_api.isChecked()
        rows: dict = {}
        root = self.model.root
        rows.setdefault(0, []).append((self.model.start_time(root), self.model.end_time(root), root))
        for ev in self.model.events:
            if ev.kind == "api" and not with_api:
                continue
            rows.setdefault(ev.depth + 1, []).append(
                (self.model.start_time(ev), self.model.end_time(ev), ev))
        self.rows = []
        for d in range(max(rows) + 1 if rows else 1):
            bars = sorted(rows.get(d, []), key=lambda b: b[0])
            self.rows.append((bars, [b[0] for b in bars]))
        self.setMinimumHeight(AXIS_H + ROW_H * max(4, len(self.rows)) + 4)
        self.update()

    # ---- coordinates ----
    def _scale(self) -> float:
        return max(1, self.width()) / max(1e-9, (self.t1 - self.t0))

    def x_of(self, t: float) -> float:
        return (t - self.t0) * self._scale()

    def t_of(self, x: float) -> float:
        return self.t0 + x / self._scale()

    def bar_at(self, pos) -> Optional[CallEvent]:
        depth = int((pos.y() - AXIS_H) // ROW_H)
        if depth < 0 or depth >= len(self.rows):
            return None
        bars, starts = self.rows[depth]
        t = self.t_of(pos.x())
        i = bisect.bisect_right(starts, t) - 1
        # thin bars: accept a few pixels of tolerance
        tol = 3 / self._scale()
        for j in (i, i + 1):
            if 0 <= j < len(bars):
                s, e, ev = bars[j]
                if s - tol <= t <= max(e, s + 1) + tol:
                    return ev
        return None

    # ---- painting ----
    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        p.fillRect(self.rect(), Qt.GlobalColor.white)
        w = self.width()
        scale = self._scale()
        fm = QFontMetrics(self.font())

        # axis
        p.fillRect(QRectF(0, 0, w, AXIS_H), QColor(240, 240, 240))
        p.setPen(QColor(90, 90, 90))
        step = _nice_step(self.t1 - self.t0, w)
        t = (int(self.t0) // step) * step
        while t <= self.t1:
            x = self.x_of(t)
            p.drawLine(int(x), AXIS_H - 5, int(x), AXIS_H)
            p.drawText(int(x) + 2, AXIS_H - 6, f"{t + 1}")  # shown as .tenet line
            t += step

        active = {id(e) for e in self.model.active_path(self._current_time())}

        for depth, (bars, starts) in enumerate(self.rows):
            y = AXIS_H + depth * ROW_H
            i = max(0, bisect.bisect_right(starts, self.t0) - 1)
            last_px = -1
            while i < len(bars):
                s, e, ev = bars[i]
                i += 1
                if s > self.t1:
                    break
                if e < self.t0:
                    continue
                x0 = self.x_of(s)
                x1 = self.x_of(max(e, s + 1))
                if x1 - x0 < 1:
                    if int(x0) == last_px:  # too small: one pixel per column
                        continue
                    x1 = x0 + 1
                last_px = int(x0)
                api = ev.kind == "api"
                rect = QRectF(x0, y + (5 if api else 1), x1 - x0, ROW_H - (10 if api else 2))
                key = ev.target
                fill = HIGHLIGHT if id(ev) in active else color_for(key, api)
                p.fillRect(rect, fill)
                if id(ev) in active:
                    p.setPen(QPen(QColor(150, 90, 0), 2))
                    p.drawRect(rect)
                elif rect.width() > 3:
                    p.setPen(QColor(255, 255, 255))
                    p.drawLine(rect.topRight(), rect.bottomRight())
                if rect.width() > 30 and not api:
                    name = self.model.name_of(ev.target) if ev.kind == "root" else self.model.display_name(ev)
                    p.setPen(Qt.GlobalColor.black)
                    p.drawText(rect.adjusted(3, 0, -2, 0), Qt.AlignmentFlag.AlignVCenter,
                               fm.elidedText(name, Qt.TextElideMode.ElideRight, int(rect.width()) - 5))

        # cursor = current trace time
        cur = self._current_time()
        if cur is not None and self.t0 <= cur <= self.t1:
            x = self.x_of(cur + 0.5)
            p.setPen(QPen(CURSOR, 2))
            p.drawLine(QPointF(x, 0), QPointF(x, self.height()))
        p.end()

    def _current_time(self):
        ctx = self.owner.ctx
        if ctx is not None and ctx.has_db():
            return ctx.db.time
        return None

    # ---- interaction ----
    def wheelEvent(self, event) -> None:
        factor = 0.8 if event.angleDelta().y() > 0 else 1.25
        t = self.t_of(event.position().x())
        lo, hi = self.model.time_range
        span = min(max(4.0, (self.t1 - self.t0) * factor), (hi - lo) + 1)
        frac = event.position().x() / max(1, self.width())
        self.t0 = t - span * frac
        self.t1 = self.t0 + span
        self._clamp()
        self.update()

    def _clamp(self) -> None:
        lo, hi = self.model.time_range
        span = self.t1 - self.t0
        if self.t0 < lo:
            self.t0, self.t1 = lo, lo + span
        if self.t1 > hi + 1:
            self.t1 = hi + 1
            self.t0 = max(lo, self.t1 - span)

    def fit(self) -> None:
        self.t0, self.t1 = self.model.time_range
        self.t1 = max(self.t1, self.t0 + 1)
        self.update()

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self._drag_x = event.position().x()
            self._dragged = False

    def mouseMoveEvent(self, event) -> None:
        if self._drag_x is not None and event.buttons() & Qt.MouseButton.LeftButton:
            dx = event.position().x() - self._drag_x
            if abs(dx) > 2 or self._dragged:
                self._dragged = True
                dt = dx / self._scale()
                self.t0 -= dt
                self.t1 -= dt
                self._clamp()
                self._drag_x = event.position().x()
                self.update()
            return
        ev = self.bar_at(event.position())
        if ev is not None:
            QToolTip.showText(event.globalPosition().toPoint(), self.owner.describe(ev), self)
        else:
            QToolTip.hideText()

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton and not self._dragged:
            ctx = self.owner.ctx
            if ctx is not None and ctx.has_db():
                t = int(self.t_of(event.position().x()))
                ctx.set_time(ctx.db.clamp_time(t))
        self._drag_x = None

    def mouseDoubleClickEvent(self, event) -> None:
        ev = self.bar_at(event.position())
        if ev is not None and ev.kind != "root":
            goto_site(self.model, ev, self.owner.navigate)

    def follow(self) -> None:
        cur = self._current_time()
        if cur is None:
            return
        if not (self.t0 <= cur <= self.t1):  # keep the cursor visible
            span = self.t1 - self.t0
            self.t0 = cur - span / 2
            self.t1 = self.t0 + span
            self._clamp()
        self.update()


def _nice_step(span, width) -> int:
    """Axis tick spacing: 1, 2, 5 x 10^n, about one tick per 90 pixels."""
    target = max(1.0, span / max(2.0, width / 90))
    base = 1
    while base * 10 <= target:
        base *= 10
    for m in (1, 2, 5, 10):
        if base * m >= target:
            return int(base * m)
    return int(base * 10)


# =====================================================================
# Call graph
# =====================================================================
class NodeItem(QGraphicsRectItem):
    def __init__(self, view: "CallGraph", key: str, api: bool, calls: list):
        super().__init__()
        self.view, self.key, self.api, self.calls = view, key, api, calls
        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, False)
        self.text = QGraphicsSimpleTextItem(self)
        self.edges_in: list = []
        self.edges_out: list = []
        self.set_active(False)

    def set_label(self, name: str) -> None:
        count = f"  ×{len(self.calls)}" if len(self.calls) > 1 else ""
        self.text.setText(("[API] " if self.api else "") + name + count)
        r = self.text.boundingRect()
        self.setRect(0, 0, r.width() + 14, r.height() + 10)
        self.text.setPos(7, 5)

    def set_active(self, on: bool) -> None:
        self.setBrush(QBrush(HIGHLIGHT if on else color_for(self.key, self.api)))
        self.setPen(QPen(QColor(150, 90, 0) if on else QColor(120, 120, 120), 2.5 if on else 1))

    def hoverEnterEvent(self, _e) -> None:
        self.setToolTip(self.view.owner.describe_node(self))

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.view.jump_next_call(self)
            event.accept()
        else:
            super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, _event) -> None:
        if self.calls:
            goto_target(self.view.model, self.calls[0], self.view.owner.navigate)


class EdgeItem(QGraphicsPathItem):
    def __init__(self, src: NodeItem, dst: NodeItem, count: int):
        super().__init__()
        self.src, self.dst, self.count = src, dst, count
        self.setZValue(-1)
        self.label = QGraphicsSimpleTextItem(f"×{count}" if count > 1 else "", self)
        f = QFont()
        f.setPointSizeF(max(6.0, f.pointSizeF() - 1))
        self.label.setFont(f)
        self.set_active(False)

    def update_path(self) -> None:
        a, b = self.src.sceneBoundingRect(), self.dst.sceneBoundingRect()
        path = QPainterPath()
        if self.src is self.dst:  # recursion: loop above the box
            p0 = QPointF(a.right() - 10, a.top())
            path.moveTo(p0)
            path.cubicTo(p0 + QPointF(30, -35), QPointF(a.left() + 10, a.top()) + QPointF(-30, -35),
                         QPointF(a.left() + 10, a.top()))
            self.label.setPos(a.center().x(), a.top() - 30)
        else:
            p0 = QPointF(a.right(), a.center().y())
            p1 = QPointF(b.left(), b.center().y())
            if p1.x() <= p0.x():  # call back to an earlier column
                p0 = QPointF(a.center().x(), a.bottom())
                p1 = QPointF(b.center().x(), b.bottom())
                c = max(p0.y(), p1.y()) + 40
                path.moveTo(p0)
                path.cubicTo(QPointF(p0.x(), c), QPointF(p1.x(), c), p1)
            else:
                dx = (p1.x() - p0.x()) / 2
                path.moveTo(p0)
                path.cubicTo(p0 + QPointF(dx, 0), p1 - QPointF(dx, 0), p1)
            mid = path.pointAtPercent(0.5)
            self.label.setPos(mid + QPointF(2, -14))
        # arrow head
        end = path.pointAtPercent(1.0)
        before = path.pointAtPercent(0.97)
        v = end - before
        ln = max(1e-6, (v.x() ** 2 + v.y() ** 2) ** 0.5)
        ux, uy = v.x() / ln, v.y() / ln
        path.moveTo(end)
        path.lineTo(end - QPointF(8 * ux - 4 * uy, 8 * uy + 4 * ux))
        path.moveTo(end)
        path.lineTo(end - QPointF(8 * ux + 4 * uy, 8 * uy - 4 * ux))
        self.setPath(path)

    def set_active(self, on: bool) -> None:
        self.setPen(QPen(CURSOR if on else QColor(150, 150, 150), 2.5 if on else 1))
        self.setZValue(0 if on else -1)


class CallGraph(QGraphicsView):
    def __init__(self, owner: "GraphWidget"):
        super().__init__()
        self.owner = owner
        self.model: CallModel = owner.model
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.nodes: dict = {}
        self.edges: dict = {}
        self._active_nodes: list = []
        self._active_edges: list = []
        self._build()

    @staticmethod
    def node_key(ev: CallEvent) -> str:
        return ("api:" if ev.kind == "api" else "fn:") + ev.target

    def _build(self) -> None:
        scene = self.scene()
        self._active_nodes, self._active_edges = [], []  # items are deleted by clear()
        scene.clear()
        self.nodes, self.edges = {}, {}
        with_api = self.owner.show_api.isChecked()
        root = self.model.root

        calls: dict = {"fn:" + root.target: [root]}
        layer: dict = {"fn:" + root.target: 0}
        first: dict = {"fn:" + root.target: -1}
        edge_count: dict = {}
        for ev in self.model.events:
            if ev.kind == "api" and not with_api:
                continue
            k = self.node_key(ev)
            calls.setdefault(k, []).append(ev)
            layer[k] = min(layer.get(k, 10 ** 9), ev.depth + 1)
            first.setdefault(k, ev.line)
            pk = "fn:" + (ev.parent.target if ev.parent is not None else root.target)
            edge_count[(pk, k)] = edge_count.get((pk, k), 0) + 1

        by_layer: dict = {}
        for k in calls:
            by_layer.setdefault(layer[k], []).append(k)
        x = 0.0
        for lv in sorted(by_layer):
            keys = sorted(by_layer[lv], key=lambda k: first[k])
            y = 0.0
            col_w = 0.0
            for k in keys:
                evs = calls[k]
                node = NodeItem(self, k, k.startswith("api:"), evs if evs[0] is not root else [root])
                node.set_label(self._name(k, evs[0]))
                node.setPos(x, y)
                scene.addItem(node)
                self.nodes[k] = node
                y += node.rect().height() + 14
                col_w = max(col_w, node.rect().width())
            x += col_w + 90

        for (a, b), n in edge_count.items():
            if a in self.nodes and b in self.nodes:
                e = EdgeItem(self.nodes[a], self.nodes[b], n)
                scene.addItem(e)
                e.update_path()
                self.edges[(a, b)] = e
        scene.setSceneRect(scene.itemsBoundingRect().adjusted(-40, -60, 40, 60))
        self.update_active()

    def _name(self, key: str, ev: CallEvent) -> str:
        if ev.kind == "root":
            return self.model.name_of(ev.target)
        return self.model.display_name(ev)

    def refresh_names(self) -> None:
        for k, node in self.nodes.items():
            node.set_label(self._name(k, node.calls[0]))
        for e in self.edges.values():
            e.update_path()

    def update_active(self) -> None:
        for n in self._active_nodes:
            n.set_active(False)
        for e in self._active_edges:
            e.set_active(False)
        self._active_nodes, self._active_edges = [], []
        ctx = self.owner.ctx
        if ctx is None or not ctx.has_db():
            return
        path = self.model.active_path(ctx.db.time)
        keys = []
        for ev in path:
            k = "fn:" + ev.target if ev.kind == "root" else self.node_key(ev)
            if k in self.nodes:
                keys.append(k)
        for k in keys:
            self.nodes[k].set_active(True)
            self._active_nodes.append(self.nodes[k])
        for a, b in zip(keys, keys[1:]):
            e = self.edges.get((a, b))
            if e is not None:
                e.set_active(True)
                self._active_edges.append(e)
        if self._active_nodes and self.owner.sync.isChecked():
            self.ensureVisible(self._active_nodes[-1], 60, 60)

    def jump_next_call(self, node: NodeItem) -> None:
        """Move the trace time to the next call of this function (wraps around)."""
        evs = [e for e in node.calls if e.kind != "root"]
        if not evs:
            return
        ctx = self.owner.ctx
        cur_line = ctx.db.time + 1 if ctx is not None and ctx.has_db() else 0
        nxt = next((e for e in evs if e.line > cur_line), evs[0])
        goto_site(self.model, nxt, self.owner.navigate)

    def wheelEvent(self, event) -> None:
        f = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(f, f)

    def fit(self) -> None:
        self.fitInView(self.scene().itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)


# =====================================================================
# Window
# =====================================================================
class GraphWidget(QWidget):
    def __init__(self, ctx, navigate: Callable[[int], None], model: CallModel):
        super().__init__()
        self.ctx = ctx
        self.navigate = navigate
        self.model = model

        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        bar = QHBoxLayout()
        self.sync = QCheckBox("Sync", self)
        self.sync.setToolTip("Follow the trace time")
        self.sync.setChecked(True)
        self.show_api = QCheckBox("APIs", self)
        self.show_api.setChecked(True)
        fit = QPushButton("Fit", self)
        fit.setToolTip("Show everything")
        hint = QLabel("wheel: zoom · drag: pan · click: go there · double-click: open", self)
        hint.setStyleSheet("color: gray;")
        bar.addWidget(self.sync)
        bar.addWidget(self.show_api)
        bar.addWidget(fit)
        bar.addStretch()
        bar.addWidget(hint)
        layout.addLayout(bar)

        self.tabs = QTabWidget(self)
        self.flame = FlameChart(self)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.flame)
        self.tabs.addTab(scroll, "Timeline (flame chart)")
        self.graph = CallGraph(self)
        self.tabs.addTab(self.graph, "Call graph")
        layout.addWidget(self.tabs)

        fit.clicked.connect(self._fit)
        self.show_api.toggled.connect(self._rebuild)
        self.sync.toggled.connect(lambda on: on and self.on_time_update())

        self.model.add_listener(self._names_changed)
        if self.ctx is not None:
            self.ctx.register_time_observer(self)
            ctx_, me, model_ = self.ctx, self, self.model
            self.destroyed.connect(
                lambda *_: (ctx_.unregister_time_observer(me), model_.remove_listener(me._names_changed))
            )

    def _fit(self) -> None:
        if self.tabs.currentIndex() == 0:
            self.flame.fit()
        else:
            self.graph.fit()

    def _rebuild(self, *_):
        self.flame._build()
        self.graph._build()

    def _names_changed(self) -> None:
        self.flame.update()
        self.graph.refresh_names()

    def on_time_update(self) -> None:
        if self.sync.isChecked():
            self.flame.follow()
        else:
            self.flame.update()
        self.graph.update_active()

    def describe(self, ev: CallEvent) -> str:
        m = self.model
        name = m.name_of(ev.target) if ev.kind == "root" else m.display_name(ev)
        if ev.kind == "api":
            return f"[API] {name}\nline {ev.line}  (called from {ev.site})"
        end = ev.end_line if ev.end_line is not None else m.root.end_line
        n = max(0, m.end_time(ev) - m.start_time(ev))
        site = f"  (called from {ev.site})" if ev.site else ""
        return f"{name}\nlines {ev.line} – {end}: {n:,} instructions{site}"

    def describe_node(self, node: NodeItem) -> str:
        evs = [e for e in node.calls if e.kind != "root"]
        name = node.text.text()
        if not evs:
            return f"{name}\n(traced function)"
        lines = ", ".join(str(e.line) for e in evs[:10]) + (" …" if len(evs) > 10 else "")
        return (f"{name}\ncalled {len(evs)} time(s), at lines {lines}\n"
                "click: next call after the current time · double-click: go to function")
