"""
Icons drawn with characters: they follow the size and the color of the text.

A character the font misses comes from another font of the system, and when no
font has it, the icon is drawn with its fallback text.

- `Glyph` is an icon and its fallback,
- `GlyphSize` is how big the icons of a group are drawn,
- `GlyphButtons` makes the flat buttons of a group, all of one size.
"""

from dataclasses import dataclass

from .qt.QtCore import QSize, Qt
from .qt.QtGui import QFont, QFontMetrics
from .qt.QtWidgets import QToolButton
from .widget import polished_metrics


@dataclass(frozen=True)
class Glyph:
    text: str
    # in the font of the text, when no font of the system has `text`
    fallback: str


PIN = Glyph("⚲", "*")
PREV_CHANGE = Glyph("❮", "<")
NEXT_CHANGE = Glyph("❯", ">")
STEP_BACK_OUT = Glyph("⇤", "|<")
STEP_BACK_OVER = Glyph("↶", "<<")
STEP_BACK_INTO = Glyph("‹", "<")
STEP_INTO = Glyph("›", ">")
STEP_OVER = Glyph("↷", ">>")
STEP_OUT = Glyph("⇥", ">|")


@dataclass(frozen=True)
class GlyphSize:
    # of the glyph, to the size of the text: the fallback keeps the size of the text
    scale: float
    # around the glyph, inside its button
    padding: int


# in a line of text, as high as the text
SMALL = GlyphSize(1.0, 0)
# beside a field: the characters of the icons are smaller than letters
LARGE = GlyphSize(1.6, 3)


def drawn(glyph: Glyph, text_font: QFont, glyph_font: QFont) -> tuple[str, QFont]:
    """The glyph in its font, or its fallback in the font of the text"""
    metrics = QFontMetrics(glyph_font)
    if all(metrics.inFontUcs4(ord(c)) for c in glyph.text):
        return glyph.text, glyph_font
    return glyph.fallback, text_font


class GlyphButtons:
    """The buttons of a group of glyphs, of one size: the biggest glyph, padded"""

    size: QSize
    _drawn: dict[Glyph, tuple[str, QFont]]

    def __init__(self, glyphs: list[Glyph], font: QFont, size: GlyphSize):
        glyph_font = QFont(font)
        glyph_font.setPointSizeF(size.scale * font.pointSizeF())
        self._drawn = {glyph: drawn(glyph, font, glyph_font) for glyph in glyphs}
        rects = [
            polished_metrics(drawn_font).tightBoundingRect(text)
            for text, drawn_font in self._drawn.values()
        ]
        # never lower than a line of text, to click a small fallback
        self.size = QSize(
            max(rect.width() for rect in rects) + 2 * size.padding,
            max(
                max(rect.height() for rect in rects) + 2 * size.padding,
                polished_metrics(font).height(),
            ),
        )

    def button(self, glyph: Glyph, tooltip: str) -> QToolButton:
        text, font = self._drawn[glyph]
        button = QToolButton()
        button.setText(text)
        button.setFont(font)
        button.setToolTip(tooltip)
        button.setAutoRaise(True)
        button.setFixedSize(self.size)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        return button
