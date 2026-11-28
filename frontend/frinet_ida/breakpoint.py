from dataclasses import dataclass
from enum import Enum

from frinet import State, Trace


class BreakpointKind(Enum):
    READ = "read"
    WRITE = "write"
    ACCESS = "access"


@dataclass(frozen=True)
class Breakpoint:
    """Represents a memory breakpoint over a specific range of addresses."""

    kind: BreakpointKind
    addr_min: int
    addr_max: int

    @property
    def size(self) -> int:
        return self.addr_max - self.addr_min + 1

    def __contains__(self, address: int) -> bool:
        return self.overlaps(address, address)

    def overlaps(self, addr_min: int, addr_max: int) -> bool:
        return addr_min <= self.addr_max and self.addr_min <= addr_max

    def hit_at(self, state: State) -> bool:
        """Whether the instruction at this time hits the breakpoint"""
        addr, size = self.addr_min, self.size
        mem = state.mem

        if self.kind != BreakpointKind.WRITE and mem.reads(addr, size):
            return True
        return self.kind != BreakpointKind.READ and bool(mem.writes(addr, size))

    def first_time(self, trace: Trace) -> int | None:
        """First hit of the breakpoint in the trace"""
        first = trace.times[0]
        if self.hit_at(trace.at(first)):
            return first
        return self.next_time(trace, after=first)

    def last_time(self, trace: Trace) -> int | None:
        """Last hit of the breakpoint in the trace"""
        last = trace.times[-1]
        if self.hit_at(trace.at(last)):
            return last
        return self.prev_time(trace, before=last)

    def prev_time(self, trace: Trace, before: int) -> int | None:
        """Nearest hit of the breakpoint strictly before `before`"""
        mem = trace.at(before).mem
        addr, size = self.addr_min, self.size

        match self.kind:
            case BreakpointKind.READ:
                return mem.prev_read(addr, size)
            case BreakpointKind.WRITE:
                return mem.prev_write(addr, size)
            case BreakpointKind.ACCESS:
                return mem.prev_access(addr, size)

    def next_time(self, trace: Trace, after: int) -> int | None:
        """Nearest hit of the breakpoint strictly after `after`"""
        mem = trace.at(after).mem
        addr, size = self.addr_min, self.size

        match self.kind:
            case BreakpointKind.READ:
                return mem.next_read(addr, size)
            case BreakpointKind.WRITE:
                return mem.next_write(addr, size)
            case BreakpointKind.ACCESS:
                return mem.next_access(addr, size)


def earliest(*times: int | None) -> int | None:
    return min((time for time in times if time is not None), default=None)


def latest(*times: int | None) -> int | None:
    return max((time for time in times if time is not None), default=None)
