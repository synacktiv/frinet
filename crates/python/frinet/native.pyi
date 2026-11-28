# Stub of the Rust extension (crates/python/src), checked by `python -m mypy.stubtest frinet.native`

from typing import final

__all__ = [
    "MODULE_MARKER_MIXED",
    "MODULE_MARKER_NONE",
    "Array",
    "Calltree",
    "CalltreeInfo",
    "CalltreeSpan",
    "Cancelled",
    "DbHandle",
    "FrinetError",
    "LoadError",
    "Module",
    "NativeError",
    "NoValueIndex",
    "RegisterInfo",
    "RegisterValues",
    "SearchMatches",
    "Task",
    "calltree_ancestors",
    "calltree_children",
    "calltree_info",
    "calltree_span",
    "calltree_span_at",
    "calltree_start",
    "calltree_step_back_over",
    "calltree_step_out",
    "calltree_step_over",
    "index_start",
    "memory_reads",
    "memory_writes",
    "module_at",
    "modules",
    "next_memory_access",
    "next_memory_read",
    "next_memory_write",
    "open",
    "prev_memory_access",
    "prev_memory_read",
    "prev_memory_write",
    "read_cstring",
    "read_memory",
    "read_memory_with_unknowns",
    "register_distinct_values",
    "register_first_time_with",
    "register_is_write_at",
    "register_last_time_with",
    "register_next_change",
    "register_next_time_with",
    "register_prev_change",
    "register_prev_time_with",
    "register_times_with",
    "register_value_at",
    "register_value_offsets",
    "register_values_in",
    "registers",
    "registers_written_at",
    "search_regex_start",
    "search_start",
    "time_end",
    "timeline_distinct_modules_in_range",
    "timeline_pixels",
    "validate_regex",
]

class FrinetError(Exception): ...
class LoadError(FrinetError): ...
class Cancelled(FrinetError): ...
class NativeError(FrinetError): ...
class NoValueIndex(FrinetError): ...

@final
class DbHandle:
    """Handle on an open database, unmapped once nothing holds it"""

@final
class Array:
    """Supports `memoryview`, read only items of `itemsize` bytes up to 8, raw bytes above"""

    @property
    def itemsize(self) -> int: ...
    def __len__(self) -> int: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

@final
class Module:
    name: str
    start: int
    # excluded
    end: int
    @property
    def size(self) -> int: ...
    def __contains__(self, addr: int) -> bool: ...

@final
class RegisterInfo:
    # trace header order, the first register is the PC
    index: int
    name: str
    byte_size: int
    # first write ..= end of the trace, None if the register is never written
    time_range: tuple[int, int] | None
    value_indexed: bool

@final
class RegisterValues:
    """One value per step, None for a step holding none"""

    # empty once every step is read
    def next_chunk(self, size: int) -> list[int | None]: ...

@final
class SearchMatches:
    """What a search found, built one match per access"""

    def __len__(self) -> int: ...
    # (addr, size, first time, last time)
    def __getitem__(self, index: int, /) -> tuple[int, int, int, int]: ...

@final
class Task:
    """Work running on a Rust thread"""

    # from 0 to 1
    def progress(self) -> float: ...
    def is_done(self) -> bool: ...
    def cancel(self) -> None: ...
    def wait(self, timeout: float | None = None) -> bool: ...
    # raises Cancelled, NativeError, or RuntimeError while running or once read
    def take(self) -> object: ...

@final
class Calltree: ...

@final
class CalltreeInfo:
    span_count: int
    complete: bool

@final
class CalltreeSpan:
    index: int
    entrypoint: int
    time_range: tuple[int, int]
    parent: int | None
    has_children: bool
    depth: int
    subtree_end: int

def open(path: str) -> DbHandle: ...
def time_end(handle: DbHandle) -> int: ...
def modules(handle: DbHandle) -> tuple[Module, ...]: ...
def module_at(handle: DbHandle, addr: int) -> int | None: ...

MODULE_MARKER_NONE: int
MODULE_MARKER_MIXED: int

# the module of each of `pixels` equal slices of time_min..=time_max, or MIXED
def timeline_pixels(
    handle: DbHandle, time_min: int, time_max: int, pixels: int
) -> list[int]: ...

# every module the PC runs in during time_min..=time_max, sorted
def timeline_distinct_modules_in_range(
    handle: DbHandle, time_min: int, time_max: int
) -> list[int]: ...

def registers(handle: DbHandle) -> list[RegisterInfo]: ...
def registers_written_at(handle: DbHandle, time: int) -> list[bool]: ...
def register_value_at(handle: DbHandle, index: int, time: int) -> int | None: ...
def register_is_write_at(handle: DbHandle, index: int, time: int) -> bool: ...

# register index by time
def register_values_in(
    handle: DbHandle, index: int, time_min: int, time_max: int
) -> RegisterValues: ...
def register_prev_change(handle: DbHandle, index: int, time: int) -> int | None: ...
def register_next_change(handle: DbHandle, index: int, time: int) -> int | None: ...
def register_first_time_with(handle: DbHandle, index: int, value: int) -> int | None: ...
def register_last_time_with(handle: DbHandle, index: int, value: int) -> int | None: ...
def register_prev_time_with(
    handle: DbHandle, index: int, value: int, time: int
) -> int | None: ...
def register_next_time_with(
    handle: DbHandle, index: int, value: int, time: int
) -> int | None: ...

# register index by value
def register_times_with(handle: DbHandle, index: int, value: int) -> Array: ...
def register_distinct_values(handle: DbHandle, index: int) -> Array: ...
def register_value_offsets(handle: DbHandle, index: int) -> Array: ...

# the memory queries read the size bytes at addr, raising ValueError outside the address space

# unknown bytes read as zero
def read_memory(handle: DbHandle, time: int, addr: int, size: int) -> bytes: ...

# None for the unknown bytes
def read_memory_with_unknowns(
    handle: DbHandle, time: int, addr: int, size: int
) -> list[int | None]: ...
def read_cstring(handle: DbHandle, time: int, addr: int, max_size: int) -> bytes: ...

# (addr, size, time of the read or write, last time its bytes are still there)
def memory_reads(
    handle: DbHandle, time: int, addr: int, size: int
) -> list[tuple[int, int, int, int]]: ...

# the writes done at `time`
def memory_writes(
    handle: DbHandle, time: int, addr: int, size: int
) -> list[tuple[int, int, int, int]]: ...
def prev_memory_read(handle: DbHandle, time: int, addr: int, size: int) -> int | None: ...
def next_memory_read(handle: DbHandle, time: int, addr: int, size: int) -> int | None: ...
def prev_memory_write(handle: DbHandle, time: int, addr: int, size: int) -> int | None: ...
def next_memory_write(handle: DbHandle, time: int, addr: int, size: int) -> int | None: ...
def prev_memory_access(handle: DbHandle, time: int, addr: int, size: int) -> int | None: ...
def next_memory_access(handle: DbHandle, time: int, addr: int, size: int) -> int | None: ...
def search_start(handle: DbHandle, needle: bytes) -> Task: ...
def search_regex_start(handle: DbHandle, pattern: str) -> Task: ...
def validate_regex(pattern: str) -> None: ...
def index_start(trace_path: str, db_path: str, node_size_order: int = 3) -> Task: ...
def calltree_start(
    handle: DbHandle,
    entries: list[int],
    exits: list[int],
    calls: list[tuple[int, int]],
) -> Task: ...
def calltree_info(tree: Calltree) -> CalltreeInfo: ...
def calltree_span(tree: Calltree, index: int) -> CalltreeSpan: ...
def calltree_children(tree: Calltree, index: int | None = None) -> list[int]: ...
def calltree_span_at(tree: Calltree, time: int) -> int | None: ...
def calltree_ancestors(tree: Calltree, index: int) -> list[int]: ...
def calltree_step_over(tree: Calltree, time: int) -> int: ...
def calltree_step_back_over(tree: Calltree, time: int) -> int: ...
def calltree_step_out(tree: Calltree, time: int) -> int: ...
