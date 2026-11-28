"""Query Frinet trace databases, built by `frinet index`.

    import frinet

    trace = frinet.open("ls.db")
    for time in trace.pc.times_with(0x401000):
        state = trace.at(time)
        print(time, state.mem.read(state.regs.rdi, 16))

A `Trace` holds no position: a `State` is the trace at one time, a `Cursor` is a `State`
whose time can move. Both read the same way.

Times are instruction indices, time and address ranges are inclusive, and a value the trace
does not know is `None`, except a memory byte `Memory.read` reads as zero.
"""

from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from os import PathLike, fsdecode
from typing import Any, Generic, TypeVar

from . import native
from .native import (
    MODULE_MARKER_MIXED,
    MODULE_MARKER_NONE,
    CalltreeSpan as Span,
    Cancelled,
    FrinetError,
    LoadError,
    Module,
    NativeError,
    NoValueIndex,
)

__all__ = [
    "MODULE_MARKER_MIXED",
    "MODULE_MARKER_NONE",
    "Calltree",
    "Cancelled",
    "Cursor",
    "FrinetError",
    "IntArray",
    "LoadError",
    "Memory",
    "MemoryAccess",
    "Module",
    "NativeError",
    "NoValueIndex",
    "Register",
    "RegisterValues",
    "Registers",
    "SearchMatch",
    "SearchMatches",
    "Span",
    "State",
    "Task",
    "Trace",
    "index",
    "open",
    "validate_regex",
]

_T = TypeVar("_T")


class _Items(Sequence[_T]):
    """Sequence over the DB, reading one item per access"""

    __slots__ = ()

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[idx] for idx in range(*index.indices(len(self)))]
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(f"{type(self).__name__} index out of range")
        return self._item(index)

    def __iter__(self) -> Iterator[_T]:
        # The length is read once, the `Sequence` mixin reads it per item
        return (self._item(index) for index in range(len(self)))

    def _item(self, index: int) -> _T:
        raise NotImplementedError


class IntArray(_Items[int]):
    """An array view directly into the DB mmap"""

    __slots__ = ("_array", "_view", "_wide")

    def __init__(self, array: native.Array) -> None:
        self._array = array
        self._view = memoryview(array)
        # `memoryview` has no format above 8 bytes, a wider scalar is decoded by `_item`
        self._wide = array.itemsize > 8

    @property
    def itemsize(self) -> int:
        return self._array.itemsize

    def __len__(self) -> int:
        return len(self._array)

    def _item(self, index: int) -> int:
        if not self._wide:
            return self._view[index]
        size = self.itemsize
        return int.from_bytes(self._view[index * size : (index + 1) * size], "little")

    def __iter__(self) -> Iterator[int]:
        if not self._wide:
            return iter(self._view)
        return super().__iter__()

    @property
    def buffer(self) -> memoryview:
        """Typed items up to 8 bytes wide, little-endian bytes above"""
        return self._view[:]

    def __repr__(self) -> str:
        return f"IntArray(len={len(self)}, itemsize={self.itemsize})"


@dataclass(frozen=True, slots=True)
class MemoryAccess:
    """A memory read or write, `last_time` being the time of a read"""

    kind: str
    addr: int
    size: int
    time: int
    last_time: int

    def __contains__(self, addr: int) -> bool:
        return self.addr <= addr < self.addr + self.size


@dataclass(frozen=True, slots=True)
class SearchMatch:
    """The searched bytes, in memory at `addr` from `first_time` to `last_time`"""

    addr: int
    size: int
    first_time: int
    last_time: int


class SearchMatches(_Items[SearchMatch]):
    """What a search found, see `Trace.search`"""

    __slots__ = ("_matches",)

    def __init__(self, matches: native.SearchMatches) -> None:
        self._matches = matches

    def __len__(self) -> int:
        return len(self._matches)

    def _item(self, index: int) -> SearchMatch:
        return SearchMatch(*self._matches[index])

    def __repr__(self) -> str:
        return f"SearchMatches({len(self)} matches)"


class Register:
    """A register of the trace, queried at an explicit time. See `Trace.regs`."""

    __slots__ = ("_handle", "byte_size", "index", "name", "time_range", "value_indexed")

    name: str
    index: int
    byte_size: int
    #: First write ..= end of the trace, `None` if the register is never written
    time_range: tuple[int, int] | None
    #: Whether the `*_time_with` queries work, it is an option of the indexer
    value_indexed: bool

    def __init__(self, handle: native.DbHandle, info: native.RegisterInfo) -> None:
        self._handle = handle
        self.name = info.name
        self.index = info.index
        self.byte_size = info.byte_size
        self.value_indexed = info.value_indexed
        self.time_range = info.time_range

    def __repr__(self) -> str:
        return f"Register({self.name!r}, byte_size={self.byte_size})"

    @property
    def first_time(self) -> int | None:
        return None if self.time_range is None else self.time_range[0]

    def value_at(self, time: int) -> int | None:
        return native.register_value_at(self._handle, self.index, time)

    def is_write_at(self, time: int) -> bool:
        """Whether the instruction at `time` wrote the register"""
        return native.register_is_write_at(self._handle, self.index, time)

    def prev_change(self, time: int) -> int | None:
        """Last time before `time` holding another value"""
        return native.register_prev_change(self._handle, self.index, time)

    def next_change(self, time: int) -> int | None:
        """First time after `time` holding another value"""
        return native.register_next_change(self._handle, self.index, time)

    def values_in(self, start: int, stop: int) -> Iterator[int | None]:
        """The value at every step of `start..=stop`, read as it is walked"""
        return _chunked(
            native.register_values_in(self._handle, self.index, start, stop)
        )

    def times_with(self, value: int) -> IntArray:
        """Every time the register holds `value`, in order"""
        return IntArray(native.register_times_with(self._handle, self.index, value))

    def count_with(self, value: int) -> int:
        return len(self.times_with(value))

    def first_time_with(self, value: int) -> int | None:
        return native.register_first_time_with(self._handle, self.index, value)

    def last_time_with(self, value: int) -> int | None:
        return native.register_last_time_with(self._handle, self.index, value)

    def prev_time_with(self, value: int, *, before: int) -> int | None:
        """Nearest time strictly before `before` holding `value`"""
        return native.register_prev_time_with(self._handle, self.index, value, before)

    def next_time_with(self, value: int, *, after: int) -> int | None:
        """Nearest time strictly after `after` holding `value`"""
        return native.register_next_time_with(self._handle, self.index, value, after)

    def distinct_values(self) -> IntArray:
        """Every value the register ever held, sorted"""
        return IntArray(native.register_distinct_values(self._handle, self.index))

    def value_counts(self) -> Sequence[int]:
        """Write count of each `distinct_values`, in the same order"""
        offsets = IntArray(native.register_value_offsets(self._handle, self.index))
        return _Counts(offsets)


def _chunked(values: native.RegisterValues) -> Iterator[int | None]:
    while chunk := values.next_chunk(4096):
        yield from chunk


class _Counts(_Items[int]):
    """Differences of consecutive offsets, computed on access"""

    __slots__ = ("_offsets",)

    def __init__(self, offsets: IntArray) -> None:
        self._offsets = offsets

    def __len__(self) -> int:
        return max(len(self._offsets) - 1, 0)

    def _item(self, index: int) -> int:
        return self._offsets[index + 1] - self._offsets[index]


class _ByName(Mapping):
    """Registers by name, by attribute as well for the console"""

    __slots__ = ("_registers",)

    def __init__(self, registers: dict[str, Register]) -> None:
        self._registers = registers

    def __len__(self) -> int:
        return len(self._registers)

    def __iter__(self) -> Iterator[str]:
        return iter(self._registers)

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"no register named {name!r}") from None

    def __dir__(self) -> list[str]:
        return [*super().__dir__(), *self._registers]


class Registers(_ByName):
    """The registers of a trace, see `Trace.regs`"""

    __slots__ = ()

    def __getitem__(self, name: str) -> Register:
        return self._registers[name]

    def __repr__(self) -> str:
        return f"Registers({', '.join(self._registers)})"


class RegisterValues(_ByName):
    """The register values at one time, see `State.regs`"""

    __slots__ = ("_at",)

    def __init__(self, at: "State", registers: dict[str, Register]) -> None:
        super().__init__(registers)
        self._at = at

    def __getitem__(self, name: str) -> int | None:
        return self._registers[name].value_at(self._at.time)

    @property
    def changed(self) -> frozenset[str]:
        """The registers the instruction at this time wrote"""
        written = native.registers_written_at(self._at.trace._handle, self._at.time)
        return frozenset(
            register.name
            for register in self._registers.values()
            if written[register.index]
        )

    def __repr__(self) -> str:
        return f"RegisterValues(time={self._at.time})"


class Memory:
    """The memory as the trace knows it at one time, see `State.mem`"""

    __slots__ = ("_at",)

    def __init__(self, at: "State") -> None:
        self._at = at

    def __repr__(self) -> str:
        return f"Memory(time={self._at.time})"

    def read(self, addr: int, size: int) -> bytes:
        """The content of `size` bytes at `addr`, the bytes the trace does not know read as zero

        Raises `ValueError` past a gibibyte, or outside the address space: the content is built
        in memory.
        """
        return native.read_memory(self._handle, self._at.time, addr, size)

    def read_with_unknowns(self, addr: int, size: int) -> list[int | None]:
        """One item per byte, `None` for the ones the trace does not know, see `read`"""
        return native.read_memory_with_unknowns(self._handle, self._at.time, addr, size)

    def read_int(
        self,
        addr: int,
        size: int = 8,
        *,
        signed: bool = False,
        byteorder: str = "little",
    ) -> int:
        return int.from_bytes(self.read(addr, size), byteorder, signed=signed)

    def cstring(self, addr: int, max_size: int = 4096) -> bytes:
        """Bytes up to the first zero or unknown byte"""
        return native.read_cstring(self._handle, self._at.time, addr, max_size)

    def reads(self, addr: int, size: int) -> list[MemoryAccess]:
        """Reads the instruction at this time does, intersecting the range"""
        events = native.memory_reads(self._handle, self._at.time, addr, size)
        return [MemoryAccess("read", *event) for event in events]

    def writes(self, addr: int, size: int) -> list[MemoryAccess]:
        """Writes the instruction at this time does, intersecting the range"""
        events = native.memory_writes(self._handle, self._at.time, addr, size)
        return [MemoryAccess("write", *event) for event in events]

    def prev_read(self, addr: int, size: int) -> int | None:
        return self._nearest(native.prev_memory_read, addr, size)

    def next_read(self, addr: int, size: int) -> int | None:
        return self._nearest(native.next_memory_read, addr, size)

    def prev_write(self, addr: int, size: int) -> int | None:
        """Nearest time before this one setting the content, a first read included"""
        return self._nearest(native.prev_memory_write, addr, size)

    def next_write(self, addr: int, size: int) -> int | None:
        """Nearest time after this one setting the content, a first read included"""
        return self._nearest(native.next_memory_write, addr, size)

    def prev_access(self, addr: int, size: int) -> int | None:
        return self._nearest(native.prev_memory_access, addr, size)

    def next_access(self, addr: int, size: int) -> int | None:
        return self._nearest(native.next_memory_access, addr, size)

    def _nearest(self, query: Callable, addr: int, size: int) -> int | None:
        return query(self._handle, self._at.time, addr, size)

    @property
    def _handle(self) -> native.DbHandle:
        return self._at.trace._handle


_PENDING = object()


class Task(Generic[_T]):
    """Work running on a Rust thread: poll it, it never calls back into Python

    Cancelling is a request: work that sees it raises `Cancelled` from `result`, never
    handing back a partial result, while work that already ended keeps its result.
    """

    __slots__ = ("_read", "_result", "_task", "name")

    def __init__(
        self, task: native.Task, read: Callable[[Any], _T], *, name: str
    ) -> None:
        self._task = task
        self._read = read
        self._result: Any = _PENDING
        self.name = name

    def __repr__(self) -> str:
        state = "done" if self.done else f"{self.progress:.0%}"
        return f"Task({self.name}, {state})"

    @property
    def progress(self) -> float:
        """How much of the work is done, from 0 to 1"""
        return self._task.progress()

    @property
    def done(self) -> bool:
        return self._task.is_done()

    def cancel(self) -> None:
        self._task.cancel()

    def wait(self, timeout: float | None = None) -> bool:
        """Waits for the end of the work, False if it is still running

        Waits in slices, so a Ctrl-C raises `KeyboardInterrupt` while the work runs rather
        than once it ends. Raises `ValueError` for a negative or NaN timeout.
        """
        return self._task.wait(timeout)

    def result(self) -> _T:
        """Waits for the end and reads the result, raising `Cancelled` or `NativeError`"""
        if self._result is _PENDING:
            self.wait()
            self._result = self._read(self._task.take())
        return self._result


class Calltree:
    """The calls of a trace, see `Trace.build_calltree`"""

    __slots__ = ("_tree", "complete", "span_count")

    span_count: int
    #: False if the build stopped on its span limit
    complete: bool

    def __init__(self, tree: native.Calltree) -> None:
        self._tree = tree
        info = native.calltree_info(tree)
        self.span_count = info.span_count
        self.complete = info.complete

    def __len__(self) -> int:
        return self.span_count

    def __repr__(self) -> str:
        return f"Calltree({self.span_count} spans, complete={self.complete})"

    def span(self, index: int) -> Span:
        return native.calltree_span(self._tree, index)

    def span_at(self, time: int) -> int | None:
        """The innermost span holding at `time`"""
        return native.calltree_span_at(self._tree, time)

    def children(self, index: int | None = None) -> list[int]:
        """The calls `index` makes, the roots of the tree when it is `None`"""
        return native.calltree_children(self._tree, index)

    def ancestors(self, index: int) -> list[int]:
        """The spans from the root down to the parent of `index`"""
        return native.calltree_ancestors(self._tree, index)

    def step_over(self, time: int) -> int:
        """Time after the call the instruction at `time` makes"""
        return native.calltree_step_over(self._tree, time)

    def step_back_over(self, time: int) -> int:
        """Time before the call returning just before `time`"""
        return native.calltree_step_back_over(self._tree, time)

    def step_out(self, time: int) -> int:
        """Time after the span holding at `time` returns"""
        return native.calltree_step_out(self._tree, time)


class Trace:
    """An indexed trace, stateless (holding no "current" time position)"""

    __slots__ = (
        "_handle",
        "modules",
        "path",
        "pc",
        "regs",
        "time_end",
    )

    path: str
    #: Time of the last event of the trace, the DB stops there
    time_end: int
    modules: tuple[Module, ...]
    regs: Registers
    #: The first register of the trace header
    pc: Register

    def __init__(self, handle: native.DbHandle, path: str) -> None:
        self._handle = handle
        self.path = path
        self.time_end = native.time_end(handle)
        self.modules = native.modules(handle)
        registers = [Register(handle, info) for info in native.registers(handle)]
        self.regs = Registers({register.name: register for register in registers})
        self.pc = registers[0]

    def __repr__(self) -> str:
        return f"Trace({self.path!r}, time_end={self.time_end})"

    @property
    def times(self) -> range:
        return range(self.time_end + 1)

    def clamp_time(self, time: int) -> int:
        """`time` held inside the trace"""
        return max(0, min(self.time_end, time))

    def _absolute_time(self, time: int) -> int:
        """`time` held inside the trace, a negative one counting back from its end"""
        if time < 0:
            time += self.time_end + 1
        return self.clamp_time(time)

    def at(self, time: int) -> "State":
        """The trace at `time`, `at(-1)` being its last time like a list index"""
        return State(self, self._absolute_time(time))

    def cursor(self, time: int = 0) -> "Cursor":
        """A cursor starting at `time`, read like `at`: `cursor(-1)` is the last time"""
        return Cursor(self, self._absolute_time(time))

    def module(self, name: str) -> Module | None:
        """First module named `name`"""
        return next((module for module in self.modules if module.name == name), None)

    def timeline_pixels(self, start: int, stop: int, pixels: int) -> list[int]:
        """The module of each of `pixels` equal slices of `start..=stop`: an index in
        `modules`, `MODULE_MARKER_NONE`, or `MODULE_MARKER_MIXED` if the PC changes of module
        during the slice

        A slice has at least one step: with more pixels than steps, the pixels share them.
        """
        return native.timeline_pixels(self._handle, start, stop, pixels)

    def timeline_distinct_modules_in_range(self, start: int, stop: int) -> list[int]:
        """Every module the PC runs in during `start..=stop`: indexes in `modules`, and
        `MODULE_MARKER_NONE` for the steps in no module"""
        return native.timeline_distinct_modules_in_range(self._handle, start, stop)

    def module_at(self, addr: int) -> Module | None:
        """The module holding `addr`, the innermost one when the system mapped a module inside
        another one"""
        index = native.module_at(self._handle, addr)
        return None if index is None else self.modules[index]

    def search(self, needle: bytes | str) -> "Task[SearchMatches]":
        """Every occurrence of `needle` in memory, UTF-8 for a `str`"""
        if isinstance(needle, str):
            needle = needle.encode()
        return _search(native.search_start(self._handle, needle))

    def search_regex(self, pattern: str) -> "Task[SearchMatches]":
        """Every match of a bytes regex in memory, raising `ValueError` if invalid"""
        return _search(native.search_regex_start(self._handle, pattern))

    def build_calltree(
        self,
        entries: list[int],
        exits: list[int],
        calls: list[tuple[int, int]],
    ) -> "Task[Calltree]":
        """Builds the call tree from the instructions of the program, on a thread of its own

        `entries` are the first instructions of the functions, `exits` the returns and tail
        jumps, and `calls` the calls with the address they return to. A call to no entry
        lasts until the PC reaches that address.
        """
        task = native.calltree_start(self._handle, entries, exits, calls)
        return Task(task, Calltree, name="call tree")


class State:
    """The trace at one time, see `Trace.at`"""

    trace: Trace

    def __init__(self, trace: Trace, time: int) -> None:
        self.trace = trace
        self._time = time

    def __repr__(self) -> str:
        return f"{type(self).__name__}(time={self.time})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, State):
            return NotImplemented
        return self.trace is other.trace and self.time == other.time

    def __hash__(self) -> int:
        return hash((id(self.trace), self.time))

    @property
    def time(self) -> int:
        return self._time

    @property
    def regs(self) -> RegisterValues:
        return RegisterValues(self, self.trace.regs._registers)

    @property
    def mem(self) -> Memory:
        return Memory(self)

    @property
    def pc(self) -> int | None:
        return self.trace.pc.value_at(self.time)

    def at(self, time: int) -> "State":
        return self.trace.at(time)

    def cursor(self) -> "Cursor":
        return self.trace.cursor(self.time)


class Cursor(State):
    """A `State` whose time can move, see `Trace.cursor`"""

    __hash__ = None  # type: ignore[assignment]

    def __init__(self, trace: Trace, time: int) -> None:
        super().__init__(trace, time)
        self._watchers: list[Callable[[Cursor], None]] = []

    @State.time.setter
    def time(self, time: int) -> None:
        self.goto(time)

    def goto(self, time: int | None) -> bool:
        """Moves to `time`, held inside the trace; False if `None` or time is unchanged"""
        if time is None:
            return False
        time = self.trace.clamp_time(time)
        if time == self._time:
            return False

        self._time = time
        for watcher in list(self._watchers):
            watcher(self)
        return True

    def step(self, count: int = 1) -> bool:
        """Moves `count` steps, backwards for a negative one, held inside the trace"""
        return self.goto(self._time + count)

    def state(self) -> State:
        """An immutable `State` at the time of the cursor"""
        return State(self.trace, self._time)

    def watch(self, callback: Callable[["Cursor"], None]) -> Callable[[], None]:
        """Calls `callback` after every move, returns what stops watching"""
        self._watchers.append(callback)
        return lambda: self._watchers.remove(callback)


def open(path: str | bytes | PathLike) -> Trace:
    """Raises `OSError` if the file cannot be read, `LoadError` if it is not a database"""
    path = fsdecode(path)
    return Trace(native.open(path), path)


def index(
    trace_path: str | bytes | PathLike,
    db_path: str | bytes | PathLike,
    *,
    node_size_order: int = 3,
) -> Task["Trace"]:
    """Indexes a trace file into a database, the result being the database opened

    Raises `OSError` if the trace cannot be read or the database cannot be created. A
    cancelled or failed indexing removes the database.
    """
    db_path = fsdecode(db_path)
    task = native.index_start(fsdecode(trace_path), db_path, node_size_order)
    return Task(task, lambda _: open(db_path), name="indexing")


def validate_regex(pattern: str) -> None:
    """Reads a search pattern without searching it, raises `ValueError` if invalid

    The reading `Trace.search_regex` does, so what it accepts is what a search looks for.
    """
    native.validate_regex(pattern)


def _search(task: native.Task) -> Task["SearchMatches"]:
    return Task(task, SearchMatches, name="search")
