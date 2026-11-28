"""
Story window: a readable narrative of the trace with links to points in time.

  * generated from the call list + the trace (story_gen.py), or opened from a
    Markdown / HTML file written by hand (same link syntax)
  * click a link to move the trace time and IDA there:
        go:<line>:<address>  line:<n>  t:<time>  ea:<address>
  * Sync: the paragraph about the current time is highlighted and scrolled to
"""
import bisect
import os
import re
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QTextCharFormat, QTextCursor, QTextFormat
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from calltree_widget import set_trace_time_at_line
from calls_model import resolve_addr
from story_gen import FrinetTraceData, StoryGenerator, TraceData, to_html, to_markdown


def link_line(href: str):
    """.tenet line a story link points to, or None."""
    m = re.match(r"^(?:go|line):(\d+)", href)
    if m:
        return int(m.group(1))
    m = re.match(r"^t:(\d+)", href)
    if m:
        return int(m.group(1)) + 1
    return None


class StoryWidget(QWidget):
    def __init__(self, ctx, navigate: Callable[[int], None], model):
        super().__init__()
        self.ctx = ctx
        self.navigate = navigate
        self.model = model
        self.blocks = []
        self.generated = True
        self._positions = []   # sorted (line, block position) from the links
        self._setup_ui()
        self.generate()
        self.model.add_listener(self._names_changed)
        if self.ctx is not None:
            self.ctx.register_time_observer(self)
            ctx_, me, model_ = self.ctx, self, self.model
            self.destroyed.connect(
                lambda *_: (ctx_.unregister_time_observer(me), model_.remove_listener(me._names_changed))
            )

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(2, 2, 2, 2)
        bar = QHBoxLayout()
        regen = QPushButton("Regenerate", self)
        regen.setToolTip("Write the story again from the call list and the trace")
        regen.clicked.connect(self.generate)
        open_b = QPushButton("Open...", self)
        open_b.setToolTip("Open a story written by hand (Markdown or HTML, same links)")
        open_b.clicked.connect(self.open_file)
        save_b = QPushButton("Save as...", self)
        save_b.clicked.connect(self.save_file)
        self.sync = QCheckBox("Sync", self)
        self.sync.setToolTip("Highlight the paragraph about the current trace time")
        self.sync.setChecked(True)
        self.sync.toggled.connect(lambda on: self.on_time_update() if on else self._clear_highlight())
        self.status = QLabel("", self)
        bar.addWidget(regen)
        bar.addWidget(open_b)
        bar.addWidget(save_b)
        bar.addWidget(self.sync)
        bar.addStretch()
        bar.addWidget(self.status)
        layout.addLayout(bar)

        self.view = QTextBrowser(self)
        self.view.setOpenLinks(False)
        self.view.anchorClicked.connect(self._on_link)
        layout.addWidget(self.view)

    # ---------- content ----------
    def _trace_data(self) -> TraceData:
        if self.ctx is not None and self.ctx.has_db():
            return FrinetTraceData(self.ctx.db)
        return TraceData()  # no DB: arguments unknown

    def generate(self) -> None:
        self.blocks = StoryGenerator(self.model, self._trace_data()).run()
        self.generated = True
        self._show_html(to_html(self.blocks))
        if self.ctx is None or not self.ctx.has_db():
            self.status.setText("Open the Frinet DB and Regenerate to see API arguments")
        else:
            self.status.setText("")

    def _names_changed(self) -> None:
        if self.generated:
            bar = self.view.verticalScrollBar().value()
            self.generate()
            self.view.verticalScrollBar().setValue(bar)

    def _show_html(self, text: str) -> None:
        self.view.setHtml(text)
        self._compact_headings()
        self._index_links()
        self.on_time_update()

    def open_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open story", os.path.dirname(self.model.path),
            "Stories (*.md *.markdown *.html *.htm *.txt);;All Files (*.*)")
        if not path:
            return
        with open(path, "r", encoding="utf-8", errors="replace") as fd:
            text = fd.read()
        self.generated = False
        if path.lower().endswith((".html", ".htm")):
            self.view.setHtml(text)
        else:
            self.view.setMarkdown(text)
        self._compact_headings()
        self._index_links()
        self.status.setText(os.path.basename(path))
        self.on_time_update()

    def save_file(self) -> None:
        base = os.path.splitext(self.model.path)[0]
        if base.endswith(".calls"):
            base = base[:-6]
        path, _ = QFileDialog.getSaveFileName(
            self, "Save story", base + ".story.md", "Markdown (*.md);;HTML (*.html)")
        if not path:
            return
        if path.lower().endswith((".html", ".htm")):
            text = to_html(self.blocks) if self.generated else self.view.toHtml()
        else:
            text = to_markdown(self.blocks) if self.generated else self.view.toMarkdown()
        with open(path, "w", encoding="utf-8", newline="\n") as fd:
            fd.write(text)
        self.status.setText(f"Saved {os.path.basename(path)}")

    def _compact_headings(self) -> None:
        """Headings only slightly larger than the text (Qt's defaults are huge).

        Qt sizes <h1>..<h3> with a relative size step (xx-large / x-large / large),
        not a point size, so the step is lowered: h1 -> large, h2/h3 -> normal, bold.
        """
        steps = {1: 1, 2: 0, 3: 0}
        doc = self.view.document()
        block = doc.begin()
        while block.isValid():
            level = block.blockFormat().headingLevel()
            if level:
                cur = QTextCursor(block)
                cur.movePosition(QTextCursor.MoveOperation.StartOfBlock)
                cur.movePosition(QTextCursor.MoveOperation.EndOfBlock, QTextCursor.MoveMode.KeepAnchor)
                cf = QTextCharFormat()
                cf.setProperty(QTextFormat.Property.FontSizeAdjustment, steps.get(level, 0))
                cf.setFontWeight(700)
                cur.mergeCharFormat(cf)
                bf = block.blockFormat()
                bf.setTopMargin(2 if level == 1 else 8)
                bf.setBottomMargin(3)
                cur.setBlockFormat(bf)
            block = block.next()

    def _index_links(self) -> None:
        """Find every time link in the document: (line, start of its paragraph)."""
        pos = []
        doc = self.view.document()
        block = doc.begin()
        while block.isValid():
            it = block.begin()
            while not it.atEnd():
                frag = it.fragment()
                if frag.isValid():
                    href = frag.charFormat().anchorHref()
                    line = link_line(href) if href else None
                    if line is not None:
                        pos.append((line, block.position()))
                it += 1
            block = block.next()
        pos.sort()
        self._positions = pos

    # ---------- links ----------
    def _on_link(self, url) -> None:
        href = url.toString()
        scheme, _, rest = href.partition(":")
        if scheme == "go":
            line, _, site = rest.partition(":")
            ea = resolve_addr(site, self.ctx) if site else None
            set_trace_time_at_line(self.ctx, int(line), ea)
            if ea is not None:
                self.navigate(ea)
        elif scheme == "line":
            set_trace_time_at_line(self.ctx, int(rest), None)
        elif scheme == "t" and self.ctx is not None and self.ctx.has_db():
            self.ctx.set_time(int(rest))
        elif scheme == "ea":
            ea = resolve_addr(rest, self.ctx)
            if ea is not None:
                self.navigate(ea)
        elif scheme in ("http", "https"):
            from PySide6.QtGui import QDesktopServices

            QDesktopServices.openUrl(url)

    # ---------- timeline synchronisation ----------
    def _clear_highlight(self) -> None:
        self.view.setExtraSelections([])

    def on_time_update(self) -> None:
        if not self.sync.isChecked() or self.ctx is None or not self.ctx.has_db():
            return
        if not self._positions:
            return
        line = self.ctx.db.time + 1
        i = bisect.bisect_right(self._positions, (line, float("inf"))) - 1
        if i < 0:
            self._clear_highlight()
            return
        best_line = self._positions[i][0]
        # the same moment can be mentioned twice (key events + steps): use the last one
        candidates = [p for (l, p) in self._positions if l == best_line]
        block_pos = max(candidates)
        cursor = QTextCursor(self.view.document())
        cursor.setPosition(block_pos)
        sel = QTextEdit.ExtraSelection()
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(255, 230, 150))
        fmt.setProperty(QTextFormat.Property.FullWidthSelection, True)
        sel.format = fmt
        sel.cursor = cursor
        sel.cursor.clearSelection()
        self.view.setExtraSelections([sel])
        self.view.setTextCursor(cursor)
        self.view.ensureCursorVisible()
