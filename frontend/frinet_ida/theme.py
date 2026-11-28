"""
Colors of the plugin. The accents are picked for the light or the dark IDA
theme, the other colors are computed from the palette of the surface they are
drawn on, so that they follow any theme.
"""

import functools
from dataclasses import dataclass

from .qt.QtGui import QColor, QPalette
from .qt.QtWidgets import QWidget
from .utils import get_qmainwindow


def is_dark(color: QColor) -> bool:
    """Perceived brightness (luma) of the color below the middle"""
    return 0.299 * color.red() + 0.587 * color.green() + 0.114 * color.blue() < 128


@functools.cache
def _main_window() -> QWidget:
    return get_qmainwindow()


def dark_theme() -> bool:
    """
    Whether IDA runs a dark theme, read at each call: the user can change it.
    IDA themes with a stylesheet, which leaves the application palette light:
    the main window has the palette of the theme.
    """
    return is_dark(_main_window().palette().color(QPalette.ColorRole.Window))


def blend(background: QColor, color: QColor, strength: float) -> QColor:
    """Opaque color between the background (0) and the color (1)"""
    return QColor(
        *(
            round(c * strength + b * (1 - strength))
            for b, c in [
                (background.red(), color.red()),
                (background.green(), color.green()),
                (background.blue(), color.blue()),
            ]
        )
    )


def muted(background: QColor, text: QColor) -> QColor:
    """Text that matters less: unknown values, status messages"""
    return blend(background, text, 0.45)


def panel(background: QColor, text: QColor) -> QColor:
    """Background of a panel that stands apart from the main one"""
    return blend(background, text, 0.06)


@dataclass(frozen=True)
class Accents:
    # memory view: memory read and written at the current time
    read: QColor
    write: QColor
    # search dialog
    error: QColor
    # timeline: the other modules cycle through pastels of draw.io
    current_time: QColor
    idb_module: QColor
    modules: tuple[QColor, ...]
    mixed_modules: QColor
    # call tree
    external: QColor
    thunk: QColor
    # disassembly lines of the current execution and of the closest ones. Not
    # green: IDA highlights in green the lines synchronized with the pseudocode
    trace_current: QColor
    trace_past: QColor
    trace_future: QColor
    # registers view: registers the instruction at this time wrote, and the
    # values pointing to a function of the IDB or to memory of the trace
    register_write: QColor
    value_function: QColor
    value_memory: QColor

    @property
    def access(self) -> QColor:
        """Read and written: purple"""
        return blend(self.read, self.write, 0.5)


LIGHT = Accents(
    read=QColor(0x00, 0x00, 0xFF),
    write=QColor(0xFF, 0x00, 0x00),
    error=QColor(0xFF, 0x00, 0x00),
    current_time=QColor(0xFF, 0x00, 0x00),
    idb_module=QColor(0x3B, 0x78, 0xD8),
    modules=(
        QColor(0xF3, 0xD0, 0x8F),
        QColor(0xCA, 0xB8, 0xD4),
        QColor(0xE5, 0xA9, 0xA7),
        QColor(0xF3, 0xE0, 0xA9),
        QColor(0xBC, 0xD8, 0xB3),
    ),
    mixed_modules=QColor(0x8C, 0x8C, 0x8C),
    external=QColor(0x00, 0x55, 0xAA),
    thunk=QColor(0x9A, 0x52, 0x00),
    trace_current=QColor(0xFF, 0xC6, 0x80),
    trace_past=QColor(0xFF, 0xB4, 0xB4),
    trace_future=QColor(0xB4, 0xCE, 0xFF),
    register_write=QColor(0xE0, 0x7A, 0x1F),
    value_function=QColor(0x2E, 0x7D, 0x32),
    value_memory=QColor(0x00, 0x6E, 0x9E),
)

DARK = Accents(
    read=QColor(0x6E, 0x96, 0xFF),
    write=QColor(0xFF, 0x64, 0x64),
    error=QColor(0xFF, 0x64, 0x64),
    current_time=QColor(0xFF, 0x64, 0x64),
    idb_module=QColor(0x5B, 0x93, 0xF0),
    modules=(
        QColor(0x8B, 0x68, 0x2A),
        QColor(0x61, 0x49, 0x6D),
        QColor(0x7A, 0x3D, 0x3B),
        QColor(0x7F, 0x6D, 0x36),
        QColor(0x4C, 0x71, 0x44),
    ),
    mixed_modules=QColor(0xB0, 0xB0, 0xB0),
    external=QColor(0x6E, 0xB4, 0xFF),
    thunk=QColor(0xFF, 0xB8, 0x6E),
    trace_current=QColor(0x6E, 0x3C, 0x00),
    trace_past=QColor(0x6A, 0x1C, 0x1C),
    trace_future=QColor(0x1C, 0x36, 0x6A),
    register_write=QColor(0xF0, 0xA0, 0x50),
    value_function=QColor(0x81, 0xC7, 0x84),
    value_memory=QColor(0x5C, 0xC8, 0xE6),
)


def accents() -> Accents:
    return DARK if dark_theme() else LIGHT


def apply_view_palette(view: QWidget) -> None:
    """
    Keep the selection of the view colored when it loses the focus, and
    alternate its rows with a translucent gray that suits any theme: the IDA
    stylesheets leave the alternate base of the light application palette, and
    a color computed from the theme goes stale, Qt restoring the palette of the
    view when the stylesheet changes
    """
    palette = QPalette(view.palette())
    active = QPalette.ColorGroup.Active

    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(128, 128, 128, 30))

    for role in (QPalette.ColorRole.Highlight, QPalette.ColorRole.HighlightedText):
        palette.setColor(
            QPalette.ColorGroup.Inactive, role, palette.color(active, role)
        )

    view.setPalette(palette)
