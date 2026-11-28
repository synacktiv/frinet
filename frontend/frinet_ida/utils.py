from typing import Sequence

from .qt import QtWidgets
from .qt.QtWidgets import QInputDialog, QMainWindow

import ida_kernwin
from frinet import Module, Trace

from .session import Session


def format_address(address: int) -> str:
    return f"0x{address:016X}"


def format_hex(val: int | None) -> str:
    return "%02X" % val if val is not None else "??"


def format_ascii(val: int | None) -> str:
    return chr(val) if val is not None and 0x20 <= val <= 0x7E else "."


def format_bytes(data: Sequence[int | None]) -> str:
    """Hex bytes separated by spaces, ?? for an unknown byte"""
    return " ".join(format_hex(val) for val in data)


def bytes_pattern(data: Sequence[int | None]) -> str:
    """Bytes regex of the data, an unknown byte matches any byte"""
    return "(?s)" + "".join("." if val is None else "\\x%02X" % val for val in data)


def get_qmainwindow() -> QMainWindow:
    """
    Get the QMainWindow instance for the current Qt runtime.
    """
    app = QtWidgets.QApplication.instance()
    return [x for x in app.allWidgets() if x.__class__ is QtWidgets.QMainWindow][0]


def select_or_ask_active_trace_module(trace: Trace, idb_name: str) -> Module | None:
    """
    Auto select loaded module from the trace based on the currently opened file in IDA.
    If none match => ask the user to pick the correct module
    """
    module_by_name = trace.module(idb_name)
    if module_by_name is not None:
        return module_by_name

    modules = trace.modules
    if len(modules) == 0:
        return None
    if len(modules) == 1:
        return modules[0]

    items = [
        f"{module.name}  {format_address(module.start)}-{format_address(module.end)}"
        for module in modules
    ]
    item, ok = QInputDialog.getItem(
        get_qmainwindow(),
        "Frinet",
        f"'{idb_name}' is not in the trace, module loaded in the IDB:",
        items,
        0,
        False,
    )
    return modules[items.index(item)] if ok else None


# Remember showing the popup : only do it once
_calltree_notice_shown = False


def notify_calltree_needed() -> None:
    """Tells the user that stepping over a call needs the call tree, once per IDA run"""

    global _calltree_notice_shown
    if _calltree_notice_shown:
        return
    _calltree_notice_shown = True

    ida_kernwin.info(
        "Stepping over and back over a call needs the call tree, "
        "which is not built yet.\n\n"
        "Open the Call tree window and press Build call tree, then Ctrl+Wheel "
        "steps over the calls of the timeline."
    )


def ask_trace_address(session: Session, default: int) -> int | None:
    """
    Asks for an address with IDA, which accepts the names and the expressions
    of the IDB. An address of the module of the IDB is mapped to the trace,
    the others are trace addresses. None if cancelled.
    """
    idb_default = session.to_idb_addr(default)
    address = ida_kernwin.ask_addr(
        default if idb_default is None else idb_default, "Go to address"
    )
    if address is None:
        return None
    trace_addr = session.to_trace_addr(address)
    return address if trace_addr is None else trace_addr
