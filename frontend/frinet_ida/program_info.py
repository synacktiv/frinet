import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import ida_ua
import idautils

from frinet import Calltree

from .session import Session
from .tasks import run_in_wait_box

MNEMONICS = {
    "metapc": {
        "calls": {"call"},
        "returns": {"ret", "retn"},
        "jumps": {"jmp"},
    },
    "arm": {
        "calls": {"bl", "blr", "blraa", "blraaz", "blrab", "blrabz"},
        "returns": {"ret", "retaa", "retab"},
        "jumps": {"b", "br", "braa", "braaz", "brab", "brabz"},
    },
}


def build_calltree(session: Session) -> Calltree | None:
    """Asks IDA what the instructions of the trace are, then builds the tree on another thread"""
    processor = ida_ida.inf_get_procname().lower()
    mnemonics = MNEMONICS.get(processor)
    if mnemonics is None:
        ida_kernwin.warning(
            "Frinet: building the call tree needs the call, return and jump "
            f"instructions of each processor, and {processor!r} is not supported yet.\n\n"
            "Pull requests are welcome at https://github.com/synacktiv/frinet"
        )
        return None

    ida_kernwin.show_wait_box("HIDECANCEL\nFrinet: reading the instructions")
    try:
        points = _points(session, mnemonics)
    finally:
        ida_kernwin.hide_wait_box()

    task = session.trace.build_calltree(*points)
    tree = run_in_wait_box(task, "Frinet: building the call tree")
    if tree is not None:
        session.set_calltree(tree)
    return tree


def ensure_calltree(session: Session) -> Calltree | None:
    if session.calltree is not None:
        return session.calltree
    return build_calltree(session)


def _points(
    session: Session, mnemonics: dict[str, set[str]]
) -> tuple[list[int], list[int], list[tuple[int, int]]]:
    entries, exits, calls = [], [], []

    for addr in session.trace.pc.distinct_values():
        ea = session.to_idb_addr(addr)
        func = None if ea is None else ida_funcs.get_func(ea)
        if func is None:
            continue

        if ea == func.start_ea:
            entries.append(addr)
        mnemonic = (ida_ua.print_insn_mnem(ea) or "").lower()
        if mnemonic in mnemonics["calls"]:
            calls.append((addr, addr + ida_bytes.get_item_size(ea)))
        elif mnemonic in mnemonics["returns"] or (
            mnemonic in mnemonics["jumps"] and _leaves(func, ea)
        ):
            exits.append(addr)

    return entries, exits, calls


def _leaves(func: ida_funcs.func_t, ea: int) -> bool:
    """Whether the jump at `ea` goes out of `func`"""
    targets = list(idautils.CodeRefsFrom(ea, False))
    return not targets or any(not ida_funcs.func_contains(func, t) for t in targets)
