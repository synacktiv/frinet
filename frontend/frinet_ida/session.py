from typing import TYPE_CHECKING

from .qt.QtCore import QObject, Signal

from frinet import Calltree, Cursor, Module, Trace

from .breakpoint import Breakpoint

if TYPE_CHECKING:
    from .search import SearchQuery


class Session(Cursor, QObject):
    """The cursor the whole interface follows, telling Qt when it moves"""

    time_changed = Signal()
    breakpoints_changed = Signal()
    calltree_changed = Signal()
    pinned_registers_changed = Signal()

    module: Module | None
    image_base: int
    pointer_size: int
    # registers shown at the top of the registers view, in the order they were pinned
    pinned_registers: list[str]
    # last query of the search dialog, offered again by the next one
    last_search_query: "SearchQuery | None"
    calltree: Calltree | None
    _breakpoints: list[Breakpoint]

    def __init__(
        self, trace: Trace, module: Module | None, image_base: int, pointer_size: int
    ):
        QObject.__init__(self)
        Cursor.__init__(self, trace, trace.times[0])

        self.module = module
        self.image_base = image_base
        self.pointer_size = pointer_size
        self.pinned_registers = []
        self.last_search_query = None
        self.calltree = None
        self._breakpoints = []

    def goto(self, time: int | None) -> bool:
        moved = super().goto(time)
        if moved:
            self.time_changed.emit()
        return moved

    def set_calltree(self, calltree: Calltree) -> None:
        self.calltree = calltree
        self.calltree_changed.emit()

    def set_pinned(self, name: str, pinned: bool) -> None:
        if pinned == (name in self.pinned_registers):
            return
        if pinned:
            self.pinned_registers.append(name)
        else:
            self.pinned_registers.remove(name)
        self.pinned_registers_changed.emit()

    @property
    def breakpoints(self) -> list[Breakpoint]:
        """The memory breakpoints, in the order they were added"""
        return list(self._breakpoints)

    def add_breakpoint(self, breakpoint: Breakpoint) -> None:
        """Breakpoints never overlap: the new one replaces those over its addresses"""
        if breakpoint in self._breakpoints:
            return
        addr_min, addr_max = breakpoint.addr_min, breakpoint.addr_max
        self._breakpoints = self._without_breakpoints_over(addr_min, addr_max)
        self._breakpoints.append(breakpoint)
        self.breakpoints_changed.emit()

    def remove_breakpoint(self, breakpoint: Breakpoint) -> None:
        if breakpoint not in self._breakpoints:
            return
        self._breakpoints.remove(breakpoint)
        self.breakpoints_changed.emit()

    def remove_breakpoints_over(self, addr_min: int, addr_max: int) -> bool:
        """Removes every breakpoint over the range, False if it has none"""
        breakpoints = self._without_breakpoints_over(addr_min, addr_max)
        if len(breakpoints) == len(self._breakpoints):
            return False
        self._breakpoints = breakpoints
        self.breakpoints_changed.emit()
        return True

    def _without_breakpoints_over(
        self, addr_min: int, addr_max: int
    ) -> list[Breakpoint]:
        return [bp for bp in self._breakpoints if not bp.overlaps(addr_min, addr_max)]

    def clear_breakpoints(self) -> None:
        if not self._breakpoints:
            return
        self._breakpoints = []
        self.breakpoints_changed.emit()

    def breakpoint_at(self, address: int) -> Breakpoint | None:
        """The breakpoint over the address, they never overlap"""
        return next((bp for bp in self._breakpoints if address in bp), None)

    def to_trace_addr(self, addr: int) -> int | None:
        """IDB address to trace address, None outside of the module"""
        if self.module is None:
            return None
        addr = addr - self.image_base + self.module.start
        return addr if addr in self.module else None

    def to_idb_addr(self, addr: int) -> int | None:
        """Trace address to IDB address, None outside of the module"""
        if self.module is None or addr not in self.module:
            return None
        return addr - self.module.start + self.image_base
