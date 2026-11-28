from typing import Callable, Optional, Any
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QMainWindow, QFileDialog
from PySide6 import QtWidgets

import os

import ida_idaapi
import ida_idp
import ida_kernwin
import ida_nalt
import idautils

from core import Ctx, IDecompiler, Db
from register_widget import RegistersWidget
from timeline_widget import TimelineDock
from memory_widget import MemoryWidget
from search_results_widget import SearchResultsWidget
from calltree_widget import CallTreeWidget
from calls_model import CallModel
from graph_widget import GraphWidget
from story_widget import StoryWidget


FRINET_MENU_ID = "frinet:menu"
FRINET_MENU = "Frinet/"
HELP_URL = "https://github.com/sigmantu1-design/frinet#readme"


class IdaDecompiler(IDecompiler):
    _ctx: Ctx

    def __init__(self):
        self.ctx = Ctx(self)
        self.timeline_windows = []
        self.registers_windows = []
        self.memory_windows = []
        self.search_results_windows = []
        self.calltree_windows = []
        self.call_models = {}  # path -> CallModel shared by tree / graph / story

    def navigate_to_addr(self, addr):
        widget = ida_kernwin.find_widget("IDA View-A")
        if widget:
            CENTER_AROUND_LINE_INDEX = 20
            ida_kernwin.ea_viewer_history_push_and_jump(
                widget, addr, 0, CENTER_AROUND_LINE_INDEX, 0
            )
        else:
            ida_kernwin.jumpto(addr)

    def refresh_view(self):
        ida_kernwin.refresh_idaview_anyway()

    def image_base(self) -> int:
        return ida_nalt.get_imagebase()

    def open_search_results_window(self, results):
        window = DockableWindow(
            "Search Results", SearchResultsWidget(self.ctx, results)
        )
        window.show()
        self.search_results_windows.append(window)

    def call_model(self, path):
        """Load a .calls.txt once; every view of it shares the same model."""
        model = self.call_models.get(path)
        if model is None:
            try:
                model = CallModel(path, self.ctx)
            except Exception as e:
                print(f"[frinet] cannot open call list {path}: {e}")
                return None
            self.call_models[path] = model
        return model

    def names_changed(self):
        for model in self.call_models.values():
            model.names_changed()

    def _show_call_view(self, title, widget, dock_target, dock_pos):
        window = DockableWindow(title, widget)
        window.show()
        window.set_dock_position(dock_target, dock_pos)
        self.calltree_windows.append(window)

    def open_calltree_window(self, path):
        model = self.call_model(path) if isinstance(path, str) else path
        if model is None:
            return
        widget = CallTreeWidget(
            self.ctx, self.navigate_to_addr, model,
            open_graph=self.open_graph_window, open_story=self.open_story_window,
        )
        self._show_call_view(
            "Call tree - " + os.path.basename(model.path), widget, "IDA View-A", ida_kernwin.DP_RIGHT
        )

    def open_graph_window(self, model):
        model = self.call_model(model) if isinstance(model, str) else model
        if model is None:
            return
        widget = GraphWidget(self.ctx, self.navigate_to_addr, model)
        self._show_call_view(
            "Call graph - " + os.path.basename(model.path), widget,
            "Output window", ida_kernwin.DP_TAB | ida_kernwin.DP_BEFORE,
        )

    def open_story_window(self, model):
        model = self.call_model(model) if isinstance(model, str) else model
        if model is None:
            return
        widget = StoryWidget(self.ctx, self.navigate_to_addr, model)
        self._show_call_view(
            "Story - " + os.path.basename(model.path), widget, "IDA View-A", ida_kernwin.DP_TAB
        )

    # "Show ..." menu items: bring back the window if it exists, else open it
    def _activate(self, windows) -> bool:
        for w in windows:
            if w.visible:
                widget = ida_kernwin.find_widget(w.title)
                if widget is not None:
                    ida_kernwin.activate_widget(widget, True)
                return True
        return False

    def show_timeline(self):
        for w in self.timeline_windows:
            w.show()  # a toolbar: just make it visible again
            return
        self.open_timeline_window()

    def show_registers(self):
        if not self._activate(self.registers_windows):
            self.open_registers_window()

    def show_memory(self):
        if not self._activate(self.memory_windows):
            self.open_memory_window()

    def open_timeline_window(self):
        window = TimelineDock(self.ctx)
        mw = get_qmainwindow()
        mw.addToolBar(Qt.ToolBarArea.RightToolBarArea, window)
        window.show()
        self.timeline_windows.append(window)

    def open_registers_window(self):
        window = DockableWindow("Registers", RegistersWidget(self.ctx), use_size_hint=True)
        # DP_SZHINT: dock it at the width the register list asks for, not half the screen
        window.set_dock_position(None, ida_kernwin.DP_RIGHT | getattr(ida_kernwin, "DP_SZHINT", 0))
        window.show()
        self.registers_windows.append(window)

    def open_memory_window(self):
        window = DockableWindow("Memory", MemoryWidget(self.ctx))
        window.set_dock_position(
            "Output window", ida_kernwin.DP_TAB | ida_kernwin.DP_BEFORE
        )
        window.show()
        self.memory_windows.append(window)

    def close_all_windows(self):
        for win in self.timeline_windows:
            win.hide()
        for win in self.registers_windows:
            win.hide()
        for win in self.memory_windows:
            win.hide()
        for win in self.search_results_windows:
            win.hide()

        self.timeline_windows = []
        self.registers_windows = []
        self.memory_windows = []
        self.search_results_windows = []


def get_qmainwindow() -> QMainWindow:
    """
    Get the QMainWindow instance for the current Qt runtime.
    """
    app = QtWidgets.QApplication.instance()
    return [x for x in app.allWidgets() if x.__class__ is QtWidgets.QMainWindow][0]


class FilePicker:
    def __init__(self, default_folder: str | None = None):
        if default_folder is None:
            default_folder = idautils.GetIdbDir()
        self._last_directory = default_folder

    def pick_file(self, title="Open Frinet DB file", filter="All Files (*.*)") -> str | None:
        path, _ = QFileDialog.getOpenFileName(None, title, self._last_directory, filter)

        if path is not None and len(path) > 0:
            self._last_directory = os.path.dirname(path) + os.sep
            return path
        else:
            return None


class DockableWindow(ida_kernwin.PluginForm):
    title: str
    visible: bool

    dock_position: Optional[Any]
    dock_target: Optional[Any]

    def __init__(self, title, widget, use_size_hint=False):
        super(DockableWindow, self).__init__()
        self.use_size_hint = use_size_hint
        self.visible = False
        self.title = title
        self.widget = widget

        self.dock_position = None
        self.dock_target = None

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.widget)
        self.parent.setLayout(layout)

    def OnClose(self, _):
        self.visible = False

    def show(self):
        options = ida_kernwin.WOPN_NOT_CLOSED_BY_ESC
        if self.use_size_hint:
            options |= getattr(ida_kernwin.PluginForm, "WOPN_DP_SZHINT", 0) or getattr(ida_kernwin, "WOPN_DP_SZHINT", 0)
        self.Show(self.title, options=options)
        self.visible = True
        self.apply_dock_position()

    def set_dock_position(self, target=None, position=None):
        self.dock_target = target
        self.dock_position = position
        if self.visible:
            self.apply_dock_position()

    def apply_dock_position(self):
        if self.dock_position is not None:
            ida_kernwin.set_dock_pos(self.title, self.dock_target, self.dock_position)

    def hide(self):
        self.Close(1)


class IDACtxEntry(ida_kernwin.action_handler_t):
    def __init__(self, action_function: Callable[[], None], enabled: Optional[Callable[[], bool]] = None):
        super(IDACtxEntry, self).__init__()
        self.action_function = action_function
        self.enabled = enabled

    def activate(self, ctx) -> int:
        self.action_function()
        return 1

    def update(self, ctx) -> int:
        if self.enabled is None:
            return ida_kernwin.AST_ENABLE_ALWAYS
        # AST_ENABLE / AST_DISABLE: IDA asks again whenever the context changes
        return ida_kernwin.AST_ENABLE if self.enabled() else ida_kernwin.AST_DISABLE


class Action:
    """
    Encapsulates IDA Pro action definition, registration, and menu attachment.
    """

    def __init__(
        self,
        action_id: str,
        label: str,
        callback: Callable[[], None],
        tooltip: str = "",
        shortcut: Optional[str] = None,
        menu_path=None,
        enabled: Optional[Callable[[], bool]] = None,
    ):
        self.action_id = action_id
        self.label = label
        self.callback = callback
        self.tooltip = tooltip
        self.shortcut = shortcut
        # one menu path, or a list of them (e.g. the Frinet menu and File/Load file)
        if menu_path is None:
            self.menu_paths = []
        elif isinstance(menu_path, str):
            self.menu_paths = [menu_path]
        else:
            self.menu_paths = list(menu_path)
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

        ok = True
        for path in self.menu_paths:
            if not ida_kernwin.attach_action_to_menu(path, self.action_id, ida_kernwin.SETMENU_APP):
                print(f"Failed to attach action '{self.action_id}' to menu '{path}'")
                ok = False
        return ok

    def attach_to_popup(self, widget, popup, popup_path) -> None:
        ida_kernwin.attach_action_to_popup(
            widget,
            popup,
            self.action_id,
            popup_path,
            ida_kernwin.SETMENU_APP,
        )


class FrinetIDAPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_MOD | ida_idaapi.PLUGIN_HIDE
    comment: str = "Frinet trace explorer"
    wanted_name: str = "Frinet"

    file_picker: FilePicker
    ctx: Ctx
    decompiler: IdaDecompiler

    open_db: Action
    prev_exec: Action
    next_exec: Action
    first_exec: Action
    last_exec: Action
    all_actions: list[Action]

    def init(self) -> int:
        self.file_picker = FilePicker()
        self.decompiler = IdaDecompiler()
        self.ctx = self.decompiler.ctx

        # The Frinet menu, in the menu bar before Help
        try:
            ida_kernwin.create_menu(FRINET_MENU_ID, "Frinet", "Help")
        except Exception as e:  # never block the plugin over the menu
            print(f"[frinet] cannot create the Frinet menu: {e}")
        M = FRINET_MENU
        has_db = self.ctx.has_db

        self.open_db = Action(
            action_id="frinet:open_db",
            label="Open ~F~rinet DB...",
            callback=self.pick_and_open_db_file,
            tooltip="Open a Frinet DB (indexed trace)",
            menu_path=[M, "File/Load file/"],
        )
        self.close_db = Action(
            action_id="frinet:close_db",
            label="Close trace",
            callback=self.ctx.close_db,
            tooltip="Close the Frinet DB and its windows",
            menu_path=M,
            enabled=has_db,
        )
        self.open_calltree = Action(
            action_id="frinet:open_calltree",
            label="Open Frinet ~c~all tree...",
            callback=self.pick_and_open_calltree,
            tooltip="Open a .calls.txt call list as a navigable tree",
            menu_path=[M, "File/Load file/"],
        )
        self.open_graph = Action(
            action_id="frinet:open_graph",
            label="Open Frinet call ~g~raph...",
            callback=lambda: self.pick_calls_then(self.decompiler.open_graph_window),
            tooltip="Open a .calls.txt as a flame chart / call graph synchronized with the timeline",
            menu_path=M,
        )
        self.open_story = Action(
            action_id="frinet:open_story",
            label="Open Frinet ~s~tory...",
            callback=lambda: self.pick_calls_then(self.decompiler.open_story_window),
            tooltip="Open the narrative of a trace (from its .calls.txt), with links to points in time",
            menu_path=M,
        )
        self.show_timeline = Action(
            action_id="frinet:show_timeline",
            label="Show Timeline",
            callback=self.decompiler.show_timeline,
            tooltip="Open the Timeline again (if you closed it)",
            menu_path=M,
            enabled=has_db,
        )
        self.show_registers = Action(
            action_id="frinet:show_registers",
            label="Show Registers",
            callback=self.decompiler.show_registers,
            tooltip="Open the Registers window again (if you closed it)",
            menu_path=M,
            enabled=has_db,
        )
        self.show_memory = Action(
            action_id="frinet:show_memory",
            label="Show Memory",
            callback=self.decompiler.show_memory,
            tooltip="Open the Memory window again (if you closed it)",
            menu_path=M,
            enabled=has_db,
        )
        self.search_memory = Action(
            action_id="frinet:search_memory",
            label="Search memory...",
            callback=self.prompt_search_memory,
            tooltip="Search the memory of the whole trace for text or a regular expression",
            menu_path=M,
            enabled=has_db,
        )
        self.first_exec = Action(
            action_id="frinet:first_execution",
            label="Go to first execution",
            callback=self.goto_first_exec,
            tooltip="Go to the first execution of the current address",
            menu_path=M,
            enabled=has_db,
        )
        self.prev_exec = Action(
            action_id="frinet:prev_execution",
            label="Go to prev execution",
            callback=self.goto_prev_exec,
            tooltip="Go to the previous execution of the current address",
            menu_path=M,
            enabled=has_db,
        )
        self.next_exec = Action(
            action_id="frinet:next_execution",
            label="Go to next execution",
            callback=self.goto_next_exec,
            tooltip="Go to the next execution of the current address",
            menu_path=M,
            enabled=has_db,
        )
        self.last_exec = Action(
            action_id="frinet:last_execution",
            label="Go to last execution",
            callback=self.goto_last_exec,
            tooltip="Go to the last execution of the current address",
            menu_path=M,
            enabled=has_db,
        )
        self.help = Action(
            action_id="frinet:help",
            label="Help (guide)...",
            callback=lambda: ida_kernwin.open_url(HELP_URL),
            tooltip="Open the Frinet for Windows guide in the browser",
            menu_path=M,
        )

        # menu order = registration order
        self.all_actions = [
            self.open_db,
            self.close_db,
            self.open_calltree,
            self.open_graph,
            self.open_story,
            self.show_timeline,
            self.show_registers,
            self.show_memory,
            self.search_memory,
            self.first_exec,
            self.prev_exec,
            self.next_exec,
            self.last_exec,
            self.help,
        ]

        for action in self.all_actions:
            action.register()

        self.ui_hooks = UIHooks(self)
        self.ui_hooks.hook()
        self.idb_hooks = RenameHooks(self.decompiler)
        self.idb_hooks.hook()

        return ida_idaapi.PLUGIN_KEEP

    def goto_prev_exec(self) -> None:
        if not self.ctx.has_db():
            return
        target_addr = ida_kernwin.get_screen_ea()
        target_addr = self.ctx.db.slide(target_addr)
        if target_addr is not None:
            self.ctx.goto_prev_exec(target_addr)

    def goto_next_exec(self) -> None:
        if not self.ctx.has_db():
            return
        target_addr = ida_kernwin.get_screen_ea()
        target_addr = self.ctx.db.slide(target_addr)
        if target_addr is not None:
            self.ctx.goto_next_exec(target_addr)

    def goto_first_exec(self) -> None:
        if not self.ctx.has_db():
            return
        target_addr = ida_kernwin.get_screen_ea()
        target_addr = self.ctx.db.slide(target_addr)
        if target_addr is not None:
            self.ctx.goto_first_exec(target_addr)

    def goto_last_exec(self) -> None:
        if not self.ctx.has_db():
            return
        target_addr = ida_kernwin.get_screen_ea()
        target_addr = self.ctx.db.slide(target_addr)
        if target_addr is not None:
            self.ctx.goto_last_exec(target_addr)

    def pick_and_open_db_file(self) -> None:
        path = self.file_picker.pick_file()
        if not path:
            return
        self.ctx.open_db(path)

    def prompt_search_memory(self) -> None:
        if not self.ctx.has_db():
            return
        from memory_widget import SearchDialog
        from PySide6.QtWidgets import QDialog

        dialog = SearchDialog(None)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            text, is_regex = dialog.get_search_params()
            if text:
                self.ctx.search(text, is_regex)

    def pick_and_open_calltree(self) -> None:
        self.pick_calls_then(self.decompiler.open_calltree_window)

    def pick_calls_then(self, open_fn) -> None:
        path = self.file_picker.pick_file(
            "Open Frinet call list", "Call lists (*.calls.txt *.txt);;All Files (*.*)"
        )
        if path:
            open_fn(path)

    def term(self) -> None:
        try:
            self.idb_hooks.unhook()
        except Exception:
            pass
        try:
            ida_kernwin.delete_menu(FRINET_MENU_ID)
        except Exception:
            pass
        print("frinet::term()")

    def render_lines(self, lines_out, widget, lines_in):
        if not self.ctx.has_db():
            return

        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type == ida_kernwin.BWN_DISASM:
            self.highlight_disassembly(self.ctx.db, lines_out, lines_in)

    def highlight_disassembly(self, db: Db, lines_out, lines_in):
        time = db.time - 1  # offset back the trail by 1

        color_by_addr = {}

        trail_length = 6
        for off in range(-trail_length, trail_length + 1):
            time_off = time + off
            if db.clamp_time(time_off) != time_off:
                continue

            value = db.pc_at(time_off)
            if value is None:
                continue
            value = db.unslide(value)
            if value is None:
                continue

            percent = (
                1.0 - ((trail_length - abs(off)) / trail_length) if off != 0 else 0.0
            )

            if off == 0:
                r, g, b = 0, 150, 0
            elif off < 0:
                r, g, b = 255, 0, 0
            else:
                r, g, b = 0, 0, 255

            color = b << 16 | g << 8 | r
            color |= (0xFF - int(0xFF * percent)) << 24

            color_by_addr[value] = color

        for section in lines_in.sections_lines:
            for line in section:
                addr = line.at.toea()
                if addr in color_by_addr:
                    color = color_by_addr[addr]
                    entry = ida_kernwin.line_rendering_output_entry_t(
                        line, ida_kernwin.LROEF_FULL_LINE, color
                    )
                    lines_out.entries.push_back(entry)


class RenameHooks(ida_idp.IDB_Hooks):
    """Refresh call-list views (real names) when something is renamed in IDA."""

    def __init__(self, decompiler):
        super().__init__()
        self.decompiler = decompiler
        self._pending = False

    def renamed(self, ea, new_name, local_name, old_name=None):
        if not self._pending and self.decompiler.call_models:
            self._pending = True
            from PySide6.QtCore import QTimer

            QTimer.singleShot(300, self._flush)  # several renames -> one refresh
        return 0

    def _flush(self):
        self._pending = False
        self.decompiler.names_changed()


class UIHooks(ida_kernwin.UI_Hooks):
    plugin: FrinetIDAPlugin

    def __init__(self, plugin: FrinetIDAPlugin):
        super().__init__()
        self.plugin = plugin

    def get_lines_rendering_info(self, lines_out, widget, lines_in):
        self.plugin.render_lines(lines_out, widget, lines_in)

    def ready_to_run(self):
        pass

    def finish_populating_widget_popup(self, widget, popup) -> None:
        if not self.plugin.ctx.has_db():
            return

        view_type = ida_kernwin.get_widget_type(widget)
        if view_type == ida_kernwin.BWN_DISASMS:
            # appear in reverse order
            self.plugin.last_exec.attach_to_popup(widget, popup, "Rename")
            self.plugin.first_exec.attach_to_popup(widget, popup, "Rename")
            self.plugin.next_exec.attach_to_popup(widget, popup, "Rename")
            self.plugin.prev_exec.attach_to_popup(widget, popup, "Rename")


def PLUGIN_ENTRY() -> ida_idaapi.plugin_t:
    return FrinetIDAPlugin()
