import functools
import itertools
import os
from typing import Any, Callable, TypeVar

import frinet
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_nalt
import idautils
from frinet import Calltree, FrinetError, Register, Task, Trace

import __main__

from . import theme
from .calltree_widget import CalltreeWidget
from .memory_widget import MemoryWidget
from .program_info import ensure_calltree
from .qt import QtWidgets, twidget_to_qwidget
from .qt.QtCore import Qt, QTimer
from .qt.QtGui import QColor
from .qt.QtWidgets import QFileDialog
from .register_widget import RegistersWidget
from .search_matches_widget import SearchMatchesWidget
from .session import Session
from .tasks import run_in_wait_box
from .timeline_widget import TimelineDock, TimelineWidget
from .trace_widget import TraceWidget
from .utils import get_qmainwindow, select_or_ask_active_trace_module
from .widget import FrinetWidget

W = TypeVar("W", bound=FrinetWidget)

TRACE_MAGIC = b"FRINET-TRACE"


class FilePicker:
    def __init__(self, default_folder: str | None = None):
        if default_folder is None:
            default_folder = idautils.GetIdbDir()
        self._last_directory = default_folder

    def pick_file(self) -> str | None:
        path, _ = QFileDialog.getOpenFileName(
            None, "Open Frinet trace or DB", self._last_directory, "All Files (*.*)"
        )

        if path is not None and len(path) > 0:
            self._last_directory = os.path.dirname(path) + os.sep
            return path
        else:
            return None


def is_raw_trace(path: str) -> bool:
    with open(path, "rb") as file:
        return file.read(len(TRACE_MAGIC)) == TRACE_MAGIC


def is_splitter(widget, orientation: Qt.Orientation) -> bool:
    return (
        isinstance(widget, QtWidgets.QSplitter) and widget.orientation() == orientation
    )


class DockableWindow(ida_kernwin.PluginForm):
    title: str
    visible: bool

    dock_position: Any | None
    dock_target: Any | None

    def __init__(self, title, widget):
        super(DockableWindow, self).__init__()
        self.visible = False
        self.title = title
        self.widget = widget

        self.dock_position = None
        self.dock_target = None

    def OnCreate(self, form):
        self.parent = twidget_to_qwidget(form)

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.widget)
        self.parent.setLayout(layout)

    def OnClose(self, _):
        # IDA destroys the widget with the form, Qt disconnects its slots
        self.visible = False

    def show(self):
        self.Show(self.title, options=ida_kernwin.WOPN_NOT_CLOSED_BY_ESC)
        self.visible = True
        if self.dock_position is not None:
            ida_kernwin.set_dock_pos(self.title, self.dock_target, self.dock_position)

    def set_dock_position(self, target=None, position=None):
        """Where the window is docked when shown, see ida_kernwin.set_dock_pos"""
        self.dock_target = target
        self.dock_position = position

    def fit_width(self):
        self._fit(Qt.Orientation.Horizontal)

    def fit_height(self):
        self._fit(Qt.Orientation.Vertical)

    def _fit(self, orientation: Qt.Orientation):
        """
        Gives the window the size of its widget: IDA docks it with a half of
        the size of its neighbour, and ignores DP_SZHINT in set_dock_pos
        """
        if not self.visible:
            return
        # the child of the splitter that holds the window, which the windows
        # docked across the splitter share
        child = self.parent
        splitter = child.parentWidget()
        while splitter is not None and not is_splitter(splitter, orientation):
            child, splitter = splitter, splitter.parentWidget()
        if splitter is None:
            return

        index = splitter.indexOf(child)
        sizes = splitter.sizes()
        hint = child.sizeHint()
        horizontal = orientation == Qt.Orientation.Horizontal
        extra = sizes[index] - (hint.width() if horizontal else hint.height())
        if extra <= 0 or len(sizes) < 2:
            return
        sizes[index] -= extra
        sizes[index - 1 if index > 0 else 1] += extra
        splitter.setSizes(sizes)

    def hide(self):
        # The form may already be closed
        if self.visible:
            self.Close(1)

    def activate(self):
        widget = ida_kernwin.find_widget(self.title)
        if widget is not None:
            ida_kernwin.activate_widget(widget, True)


class IDACtxEntry(ida_kernwin.action_handler_t):
    def __init__(
        self,
        action_function: Callable[[], None],
        enabled: Callable[[], bool] | None = None,
    ):
        super(IDACtxEntry, self).__init__()
        self.action_function = action_function
        self.enabled = enabled

    def activate(self, ctx) -> int:
        self.action_function()
        return 1

    def update(self, ctx) -> int:
        if self.enabled is None:
            return ida_kernwin.AST_ENABLE_ALWAYS
        # AST_ENABLE and AST_DISABLE: IDA asks again when anything changes
        return action_state(self.enabled)


def action_state(enabled: Callable[[], bool]) -> int:
    return ida_kernwin.AST_ENABLE if enabled() else ida_kernwin.AST_DISABLE


class Action:
    def __init__(
        self,
        action_id: str,
        label: str,
        callback: Callable[[], None],
        tooltip: str = "",
        shortcut: str | None = None,
        menu_paths: tuple[str, ...] = (),
        enabled: Callable[[], bool] | None = None,
    ):
        self.action_id = action_id
        self.label = label
        self.callback = callback
        self.tooltip = tooltip
        self.shortcut = shortcut
        self.menu_paths = menu_paths
        self.enabled = enabled

    def register(self) -> bool:
        action_desc = ida_kernwin.action_desc_t(
            self.action_id,
            self.label,
            IDACtxEntry(self.callback, self.enabled),
            self.shortcut,
            self.tooltip,
            -1,
        )

        if not ida_kernwin.register_action(action_desc):
            print(f"Failed to register action '{self.action_id}'")
            return False

        for menu_path in self.menu_paths:
            if not ida_kernwin.attach_action_to_menu(
                menu_path, self.action_id, ida_kernwin.SETMENU_APP
            ):
                print(
                    f"Failed to attach action '{self.action_id}' to menu '{menu_path}'"
                )
                return False

        return True

    def unregister(self) -> None:
        ida_kernwin.unregister_action(self.action_id)

    def update_state(self) -> None:
        """For a change IDA does not see, like the trace opening or closing"""
        if self.enabled is not None:
            ida_kernwin.update_action_state(self.action_id, action_state(self.enabled))

    def attach_to_popup(self, widget, popup, popup_path) -> None:
        ida_kernwin.attach_action_to_popup(
            widget,
            popup,
            self.action_id,
            popup_path,
            ida_kernwin.SETMENU_APP,
        )


MENU_ID = "frinet:menu"
MENU_PATH = "Frinet/"
VIEW_MENU_PATH = "Frinet/View/"

TRAIL_LENGTH = 5
TRAIL_MIN_STRENGTH = 0.35

#: name the cursor of the open trace takes in the IDA console
CONSOLE_NAME = "frinet_cursor"


def disassembly_background_color(widget) -> QColor | None:
    """Background of a disassembly view, from the IDA theme"""
    qwidget = twidget_to_qwidget(widget)
    # IDAView has the qproperty-line-bg-default of the theme stylesheet
    for view in [qwidget, *qwidget.findChildren(QtWidgets.QAbstractScrollArea)]:
        color = view.property("line_bg_default")
        if isinstance(color, QColor) and color.isValid():
            return color
    return None


def trail_color(time_offset: int, background: QColor) -> QColor:
    accents = theme.accents()
    if time_offset == 0:
        return accents.trace_current
    color = accents.trace_past if time_offset < 0 else accents.trace_future
    fade = (abs(time_offset) - 1) / (TRAIL_LENGTH - 1)
    strength = 1 - (1 - TRAIL_MIN_STRENGTH) * fade
    return theme.blend(background, color, strength)


def bgr(color: QColor) -> int:
    """Opaque color in the order the IDA line rendering wants"""
    return 0xFF << 24 | color.blue() << 16 | color.green() << 8 | color.red()


class FrinetIDAPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_MOD | ida_idaapi.PLUGIN_HIDE
    comment: str = "Frinet trace explorer"
    wanted_name: str = "Frinet"

    file_picker: FilePicker
    session: Session | None
    timeline: TimelineDock | None
    trace_window: DockableWindow | None
    registers: DockableWindow | None
    calltree: DockableWindow | None
    memory_views: dict[int, DockableWindow]
    last_memory_view_id: int | None
    search_windows: list[DockableWindow]

    # actions of the Frinet menu, in their order
    menu_actions: list[Action]
    step_actions: list[Action]
    # in the order of the disassembly context menu
    exec_actions: list[Action]
    ui_hooks: "UIHooks"
    # of the disassembly, the last one found
    background: QColor

    def init(self) -> int:
        self.file_picker = FilePicker()
        self.session = None
        self.timeline = None
        self.trace_window = None
        self.registers = None
        self.calltree = None
        self.memory_views = {}
        self.last_memory_view_id = None
        self.search_windows = []
        self.background = QColor(Qt.GlobalColor.white)

        has_trace = lambda: self.session is not None
        self.menu_actions = [
            Action(
                action_id="frinet:open_trace",
                label="Open ~F~rinet trace or DB...",
                callback=self.pick_and_open,
                tooltip="Open a Frinet DB, or a raw trace after indexing it into a DB",
                menu_paths=("File/Load file/", MENU_PATH),
            ),
            Action(
                action_id="frinet:trace",
                label="Trace",
                callback=self.show_trace_window,
                tooltip="Show the trace window: the time and the memory accesses",
                menu_paths=(VIEW_MENU_PATH,),
                enabled=has_trace,
            ),
            Action(
                action_id="frinet:timeline",
                label="Timeline",
                callback=self.show_timeline,
                tooltip="Show the timeline of the trace",
                menu_paths=(VIEW_MENU_PATH,),
                enabled=has_trace,
            ),
            Action(
                action_id="frinet:registers",
                label="Registers",
                callback=self.show_registers,
                tooltip="Show the registers window",
                menu_paths=(VIEW_MENU_PATH,),
                enabled=has_trace,
            ),
            Action(
                action_id="frinet:calltree",
                label="Call tree",
                callback=self.show_calltree,
                tooltip="Show the call tree of the trace",
                menu_paths=(VIEW_MENU_PATH,),
                enabled=has_trace,
            ),
            Action(
                action_id="frinet:new_memory_view",
                label="New Memory view",
                callback=self.open_memory_view,
                tooltip="Open a new memory view",
                menu_paths=(VIEW_MENU_PATH,),
                enabled=has_trace,
            ),
            Action(
                action_id="frinet:close_trace",
                label="Close trace",
                callback=self.close_trace,
                tooltip="Close the Frinet trace and its windows",
                menu_paths=(MENU_PATH,),
                enabled=has_trace,
            ),
        ]
        self.step_actions = [
            self._step_action(
                "step_over",
                "Step over",
                "Go after the call made by the current instruction",
                lambda tree, time: tree.step_over(time),
            ),
            self._step_action(
                "step_out",
                "Step out",
                "Go after the return of the current function",
                lambda tree, time: tree.step_out(time),
            ),
        ]
        self.exec_actions = [
            self._exec_action(
                "prev",
                "previous",
                lambda pc, addr, time: pc.prev_time_with(addr, before=time),
            ),
            self._exec_action(
                "next",
                "next",
                lambda pc, addr, time: pc.next_time_with(addr, after=time),
            ),
            self._exec_action(
                "first", "first", lambda pc, addr, _: pc.first_time_with(addr)
            ),
            self._exec_action(
                "last", "last", lambda pc, addr, _: pc.last_time_with(addr)
            ),
        ]

        ida_kernwin.create_menu(MENU_ID, "Frinet", "Help")
        for action in self._actions():
            action.register()

        self.ui_hooks = UIHooks(self)
        self.ui_hooks.hook()

        return ida_idaapi.PLUGIN_KEEP

    def term(self) -> None:
        # called at each database close (PLUGIN_PROC)
        self.close_trace()
        self.ui_hooks.unhook()
        for action in self._actions():
            action.unregister()
        ida_kernwin.delete_menu(MENU_ID)

    def _actions(self) -> list[Action]:
        return [*self.menu_actions, *self.step_actions, *self.exec_actions]

    def _step_action(
        self,
        name: str,
        label: str,
        tooltip: str,
        step: Callable[[Calltree, int], int],
    ) -> Action:
        def goto() -> None:
            session = self.session
            if session is None:
                return
            tree = ensure_calltree(session)
            if tree is not None:
                session.goto(step(tree, session.time))

        return Action(
            action_id=f"frinet:{name}",
            label=label,
            callback=goto,
            tooltip=tooltip,
            enabled=lambda: self.session is not None,
        )

    def _exec_action(
        self,
        name: str,
        adjective: str,
        find: Callable[[Register, int, int], int | None],
    ) -> Action:
        """Action that goes to an execution of the address under the cursor"""

        def goto() -> None:
            session = self.session
            if session is None:
                return
            addr = session.to_trace_addr(ida_kernwin.get_screen_ea())
            if addr is None:
                return
            time = find(session.trace.pc, addr, session.time)
            if time is not None:
                session.goto(time)

        return Action(
            action_id=f"frinet:{name}_execution",
            label=f"Go to {name} execution",
            callback=goto,
            tooltip=f"Go to the {adjective} execution of the current address",
            enabled=lambda: self.session is not None,
        )

    def pick_and_open(self) -> None:
        path = self.file_picker.pick_file()
        if not path:
            return
        if not is_raw_trace(path):
            self.open_trace(path)
            return

        db_path = path + ".db"
        if os.path.exists(db_path):
            answer = ida_kernwin.ask_yn(
                ida_kernwin.ASKBTN_YES,
                f"{db_path} exists, open it instead of indexing the trace again?",
            )
            if answer == ida_kernwin.ASKBTN_CANCEL:
                return
            if answer == ida_kernwin.ASKBTN_YES:
                self.open_trace(db_path)
                return
        self.index_and_open(path, db_path)

    def index_and_open(self, trace_path: str, db_path: str) -> None:
        # the database may be the one open, mapped in memory
        self.close_trace()
        try:
            task = frinet.index(trace_path, db_path)
            trace = run_in_wait_box(task, "Frinet: indexing the trace")
        except (OSError, FrinetError) as e:
            print("Frinet: indexing failed :", e)
            return
        if trace is not None:
            self.show_trace(trace)

    def open_trace(self, path: str) -> None:
        try:
            trace = frinet.open(path)
        except Exception as e:
            print("Open trace failed :", e)
            return
        self.show_trace(trace)

    def show_trace(self, trace: Trace) -> None:
        self.close_trace()
        module = select_or_ask_active_trace_module(trace, ida_nalt.get_root_filename())
        if module is None:
            print("Frinet: no module selected, the IDA view will not follow the trace")
        pointer_size = 8 if ida_ida.inf_is_64bit() else 4
        self.session = Session(trace, module, ida_nalt.get_imagebase(), pointer_size)
        self.session.time_changed.connect(self.on_time_changed)
        self._expose_to_console(self.session)
        self.show_timeline()
        self.show_registers()
        self.show_trace_window()
        self.open_memory_view()
        self.show_calltree()
        self._update_action_states()

    @staticmethod
    def _expose_to_console(session: Session | None) -> None:
        """`frinet_cursor` in the IDA console: the same cursor the windows follow"""
        if session is None:
            vars(__main__).pop(CONSOLE_NAME, None)
        else:
            setattr(__main__, CONSOLE_NAME, session)

    def close_trace(self) -> None:
        if self.timeline is not None:
            self.timeline.close()
            get_qmainwindow().removeToolBar(self.timeline)
            self.timeline.deleteLater()
            self.timeline = None
        windows = [
            self.trace_window,
            self.registers,
            self.calltree,
            *self.memory_views.values(),
            *self.search_windows,
        ]
        for window in windows:
            if window is not None:
                window.hide()
        self.trace_window = None
        self.registers = None
        self.calltree = None
        self.memory_views = {}
        self.last_memory_view_id = None
        self.search_windows = []
        self.session = None
        self._expose_to_console(None)
        self._update_action_states()

    def _update_action_states(self) -> None:
        for action in self._actions():
            action.update_state()

    def _widget(self, cls: type[W], *args: Any) -> W:
        """Creates a Frinet widget, its requests connected to the plugin"""
        assert self.session is not None
        widget = cls(self.session, self.memory_view_ids, *args)
        widget.follow_in_memory.connect(self.follow_in_memory)
        widget.follow_in_last_memory.connect(self.follow_in_last_memory)
        widget.open_search_matches.connect(self.open_search_matches)
        return widget

    def show_timeline(self) -> None:
        if self.session is None:
            return
        if self.timeline is None:
            self.timeline = TimelineDock(self._widget(TimelineWidget))
            get_qmainwindow().addToolBar(Qt.ToolBarArea.RightToolBarArea, self.timeline)
        # the user can hide the toolbar from the context menu of the toolbars
        self.timeline.show()

    def show_registers(self) -> None:
        if self.session is None:
            return
        if self.registers is not None and self.registers.visible:
            self.registers.activate()
            return
        self.registers = DockableWindow("Registers", self._widget(RegistersWidget))
        self.registers.set_dock_position(None, ida_kernwin.DP_RIGHT)
        self._show(self.registers)

    def show_trace_window(self) -> None:
        if self.session is None:
            return
        if self.trace_window is not None and self.trace_window.visible:
            self.trace_window.activate()
            return
        self.trace_window = DockableWindow("Trace", self._widget(TraceWidget))
        self.trace_window.set_dock_position("Registers", ida_kernwin.DP_TOP)
        self._show(self.trace_window)

    def show_calltree(self) -> None:
        if self.session is None:
            return
        if self.calltree is not None and self.calltree.visible:
            self.calltree.activate()
            return
        self.calltree = DockableWindow("Call tree", self._widget(CalltreeWidget))
        self.calltree.set_dock_position("Registers", ida_kernwin.DP_BOTTOM)
        self._show(self.calltree)

    def memory_view_ids(self) -> list[int]:
        """Ids of the open memory views, the window of the view N is "Memory N" """
        self.memory_views = {
            view_id: window
            for view_id, window in self.memory_views.items()
            if window.visible
        }
        return sorted(self.memory_views)

    def open_memory_view(self) -> DockableWindow | None:
        if self.session is None:
            return None
        ids = self.memory_view_ids()
        view_id = next(i for i in itertools.count(1) if i not in ids)

        widget = self._widget(MemoryWidget)
        widget.focused.connect(functools.partial(self._memory_view_focused, view_id))
        window = DockableWindow(f"Memory {view_id}", widget)
        if ids:
            # a new tab next to the other memory views
            window.set_dock_position(f"Memory {ids[-1]}", ida_kernwin.DP_TAB)
        else:
            window.set_dock_position(
                "Output window", ida_kernwin.DP_TAB | ida_kernwin.DP_BEFORE
            )
        self._show(window)
        self.memory_views[view_id] = window
        self.last_memory_view_id = view_id
        return window

    def _memory_view_focused(self, view_id: int) -> None:
        self.last_memory_view_id = view_id

    def follow_in_last_memory(self, address: int) -> None:
        """Shows the address in the memory view focused last, or in a new one"""
        self.follow_in_memory(address, self.last_memory_view_id)

    def follow_in_memory(self, address: int, view_id: int | None) -> None:
        """Shows the address in the memory view view_id, or in a new one if None"""
        window = self.memory_views.get(view_id) if view_id is not None else None
        if window is None or not window.visible:
            window = self.open_memory_view()
            if window is None:
                return
        window.widget.follow_address(address)
        window.activate()

    def open_search_matches(self, query: str, task: Task) -> None:
        if self.session is None:
            task.cancel()
            return
        # one window per search, IDA identifies the windows by their title, and
        # a long query (the bytes of a selection) would take the whole tab bar
        short = query if len(query) <= 32 else query[:31] + "…"
        title = f"Search: {short}"
        n = 1
        while ida_kernwin.find_widget(title) is not None:
            n += 1
            title = f"Search: {short} ({n})"
        window = DockableWindow(title, self._widget(SearchMatchesWidget, task, query))
        self._show(window)
        self.search_windows.append(window)

    def _show(self, window: DockableWindow) -> None:
        window.show()
        # docking a window splits the space evenly again, and IDA lays out
        # the windows from the event loop
        QTimer.singleShot(0, self._fit_windows)

    def _fit_windows(self) -> None:
        if self.registers is not None:
            self.registers.fit_width()
        if self.trace_window is not None:
            self.trace_window.fit_height()

    def on_time_changed(self) -> None:
        """The IDA view follows the PC"""
        session = self.session
        if session is None:
            return
        pc = session.pc
        addr = session.to_idb_addr(pc) if pc is not None else None
        if addr is not None:
            widget = ida_kernwin.find_widget("IDA View-A")
            if widget:
                CENTER_AROUND_LINE_INDEX = 20
                ida_kernwin.ea_viewer_history_push_and_jump(
                    widget, addr, 0, CENTER_AROUND_LINE_INDEX, 0
                )
            else:
                ida_kernwin.jumpto(addr)
        ida_kernwin.refresh_idaview_anyway()

    def highlight_disassembly(self, widget, lines_out, lines_in) -> None:
        session = self.session
        if session is None:
            return
        # read at each rendering: the user can change the theme
        self.background = disassembly_background_color(widget) or self.background
        trace = session.trace
        time = session.time

        color_by_addr = {}

        first = trace.clamp_time(time - TRAIL_LENGTH)
        values = list(trace.pc.values_in(first, trace.clamp_time(time + TRAIL_LENGTH)))

        # the closest executions last, they win when an address is executed twice
        offsets = sorted((first + idx - time for idx in range(len(values))), key=abs)
        for off in reversed(offsets):
            value = values[off + time - first]
            if value is None:
                continue
            addr = session.to_idb_addr(value)
            if addr is None:
                continue

            color_by_addr[addr] = trail_color(off, self.background)

        for section in lines_in.sections_lines:
            for line in section:
                addr = line.at.toea()
                if addr in color_by_addr:
                    color = bgr(color_by_addr[addr])
                    entry = ida_kernwin.line_rendering_output_entry_t(
                        line, ida_kernwin.LROEF_FULL_LINE, color
                    )
                    lines_out.entries.push_back(entry)


class UIHooks(ida_kernwin.UI_Hooks):
    plugin: FrinetIDAPlugin

    def __init__(self, plugin: FrinetIDAPlugin):
        super().__init__()
        self.plugin = plugin

    def get_lines_rendering_info(self, lines_out, widget, lines_in):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            self.plugin.highlight_disassembly(widget, lines_out, lines_in)

    def finish_populating_widget_popup(self, widget, popup) -> None:
        if self.plugin.session is None:
            return

        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASMS:
            # each action is inserted right after "Rename", so in reverse order
            for action in reversed(self.plugin.exec_actions):
                action.attach_to_popup(widget, popup, "Rename")
