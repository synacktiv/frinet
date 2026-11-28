import functools
from typing import Callable

from .qt.QtCore import QEvent, QPoint, Signal
from .qt.QtGui import QAction, QFont, QFontMetrics
from .qt.QtWidgets import QApplication, QLabel, QMenu, QWidget

from .session import Session

MAX_ADDR = 1 << 64
MAX_MENU_BYTES = 64 * 1024


def monospace_font(point_size: int | None = None, bold: bool = False) -> QFont:
    font = QFont("monospace") if point_size is None else QFont("monospace", point_size)
    font.setStyleHint(QFont.StyleHint.Monospace)
    font.setBold(bold)
    return font


def polished_metrics(font: QFont) -> QFontMetrics:
    """Of the font on a label: the IDA stylesheet changes the metrics"""
    probe = QLabel()
    probe.setFont(font)
    probe.ensurePolished()
    return probe.fontMetrics()


class FrinetWidget(QWidget):
    """
    Base of the Frinet widgets. A widget follows the time of the session, and
    asks the plugin with its signals for what is outside of it: the plugin
    connects them for every widget it creates.
    """

    # (address, id of the memory view, None for a new view)
    follow_in_memory = Signal(object, object)
    # address, shown in the memory view focused last
    follow_in_last_memory = Signal(object)
    # (query, the running frinet.Task[frinet.SearchMatches])
    open_search_matches = Signal(str, object)

    session: Session
    _memory_view_ids: Callable[[], list[int]]

    def __init__(self, session: Session, memory_view_ids: Callable[[], list[int]]):
        super().__init__()
        self.session = session
        self._memory_view_ids = memory_view_ids
        # Qt disconnects it when the widget is destroyed
        session.time_changed.connect(self.on_time_update)

    def on_time_update(self) -> None:
        """Called when the time of the session changes"""

    # theme

    def changeEvent(self, event) -> None:
        super().changeEvent(event)
        if event.type() in (QEvent.Type.PaletteChange, QEvent.Type.StyleChange):
            self.on_palette_change()

    def on_palette_change(self) -> None:
        """Called when the palette changes, with the theme"""

    def memory_view_ids(self) -> list[int]:
        """Ids of the open memory views, the window of the view N is "Memory N" """
        return self._memory_view_ids()

    # The context menus are built by a method of the widget, apart from the
    # modal exec, so that the tests can trigger their actions.

    def show_menu(self, menu: QMenu, global_pos: QPoint) -> None:
        menu.exec(global_pos)
        menu.deleteLater()

    @staticmethod
    def add_action(menu: QMenu, text: str, callback: Callable[[], None]) -> QAction:
        action = menu.addAction(text)
        # triggered passes a 'checked' argument
        action.triggered.connect(lambda checked=False: callback())
        return action

    def add_copy_action(self, menu: QMenu, text: str, value: Callable[[], str]) -> None:
        """Lazy computed clipboard copy"""
        self.add_action(menu, text, lambda: QApplication.clipboard().setText(value()))

    def add_follow_address_actions(
        self, menu: QMenu, address: int | None, what: str | None = None
    ) -> None:
        if address is None or not 0 <= address < MAX_ADDR:
            return

        for view_id in [*self.memory_view_ids(), None]:
            view = "new Memory view" if view_id is None else f"Memory {view_id}"

            if what is None:
                title = f"Follow in {view}"
            else:
                title = f"Follow {what} in {view}"

            self.add_action(
                menu,
                title,
                functools.partial(self.follow_in_memory.emit, address, view_id),
            )
