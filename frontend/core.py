from typing import Protocol, Optional, Callable

import frinet_db
from frinet_db import FrinetDb, RegisterDb, AllRegisterSnapshot, Metadata, SearchResult
from arch import Arch, detect_arch


class IDecompiler(Protocol):
    """
    decompiler-specific interface
    """

    def navigate_to_addr(self, addr: int) -> None: ...
    def refresh_view(self) -> None: ...
    def open_search_results_window(self, results: list[SearchResult]) -> None: ...
    def open_timeline_window(self) -> None: ...
    def open_registers_window(self) -> None: ...
    def open_memory_window(self) -> None: ...
    def close_all_windows(self) -> None: ...


class TimeObserver(Protocol):
    def on_time_update(self) -> None: ...


PC_REG_NAMES = ["pc", "rip"]


class Db:
    frinet_db: FrinetDb
    _metadata: Metadata
    pc: RegisterDb
    time_bbox: tuple[int, int]

    _current_time: int

    def __init__(self, path: str, arch: Arch):
        self.frinet_db = frinet_db.open(path)
        self._metadata = self.frinet_db.metadata

        pc_name = arch.pc_register_name()
        pc = self.frinet_db.register(pc_name)
        if pc is None:
            raise Exception(f"PC register not found '{pc_name}' :/")

        self.pc = pc
        self.time_bbox = self.pc.time_bbox()
        self._current_time = self.time_bbox[0]

    def register_names(self) -> list[str]:
        return self._metadata.register_names

    def slide(self, ptr: int) -> Optional[int]:
        slide = self._metadata.alsr_slide
        if slide is None:
            return None
        return slide + ptr

    def unslide(self, ptr: int) -> int | None:
        slide = self._metadata.alsr_slide
        if slide is not None and ptr > slide:
            return ptr - slide
        else:
            return None

    def registers_snapshot(self) -> AllRegisterSnapshot:
        return self.frinet_db.registers_snapshot(self.time)

    def pc_at(self, time: int) -> int | None:
        return self.pc.value_at(time)

    @property
    def time(self) -> int:
        return self._current_time

    def clamp_time(self, time: int) -> int:
        [tmin, tmax] = self.time_bbox
        return min(tmax, max(time, tmin))

    def memory_bytes_at(self, time: int, addr: int, bytes: int) -> list[int | None]:
        return self.frinet_db.memory_bytes_at(time, addr, bytes)

    def memory_bytes(self, addr: int, bytes: int) -> list[int | None]:
        return self.memory_bytes_at(self.time, addr, bytes)


class Ctx:
    """
    Global context (decompiler-generic)
    """

    _decompiler: IDecompiler
    _db: Db | None
    _time_observers: set[TimeObserver]
    arch: Arch

    def __init__(self, decompiler: IDecompiler):
        self.arch = detect_arch()
        self._time_observers = set()
        self._decompiler = decompiler
        self._db = None

    @property
    def db(self) -> Db:
        if self._db is None:
            raise Exception("No db is currently loaded")
        return self._db

    def has_db(self) -> bool:
        return self._db is not None

    def open_db(self, path: str) -> None:
        if self.has_db():
            self.close_db()

        try:
            self._db = Db(path, self.arch)
        except Exception as e:
            print("Open DB failed :", e)
            return

        self._decompiler.open_timeline_window()
        self._decompiler.open_registers_window()
        self._decompiler.open_memory_window()

    def close_db(self) -> None:
        self._decompiler.close_all_windows()
        self._db = None

    def register_time_observer(self, observer: TimeObserver) -> None:
        self._time_observers.add(observer)

    def unregister_time_observer(self, observers: TimeObserver) -> None:
        self._time_observers.remove(observers)

    def search(self, query: str, is_regex: bool) -> None:
        try:
            results = self.db.frinet_db.search(query, regex=is_regex)
            self._decompiler.open_search_results_window(results)
        except Exception as e:
            raise e

    def goto_first_exec(self, target_pc: int) -> None:
        self._goto_generic(target_pc, self.db.pc.first_time_with)

    def goto_last_exec(self, target_pc: int) -> None:
        self._goto_generic(target_pc, self.db.pc.last_time_with)

    def goto_prev_exec(self, target_pc: int) -> None:
        time = self.db.time
        self._goto_relative_generic(time, target_pc, self.db.pc.prev_time_with)

    def goto_next_exec(self, target_pc: int) -> None:
        time = self.db.time
        self._goto_relative_generic(time, target_pc, self.db.pc.next_time_with)

    def _goto_generic(self, target_pc: int, function: Callable[[int], Optional[int]]):
        new_time = function(target_pc)
        if new_time is not None:
            self.set_time(new_time)

    def _goto_relative_generic(
        self, time: int, target_pc: int, function: Callable[[int, int], Optional[int]]
    ):
        new_time = function(time, target_pc)
        if new_time is not None:
            self.set_time(new_time)

    def set_time(self, new_time: int) -> None:
        db = self.db
        new_time = db.clamp_time(new_time)

        if new_time == db._current_time:
            return

        db._current_time = new_time

        dead = []
        for observer in list(self._time_observers):
            try:
                observer.on_time_update()
            except RuntimeError as err:
                # window was closed by IDA: its Qt object is gone, forget it
                if "already deleted" in str(err):
                    dead.append(observer)
                else:
                    print(err)
            except Exception as err:
                print(err)
        for observer in dead:
            self._time_observers.discard(observer)

        pc = db.pc_at(new_time)
        if pc is not None:
            unslide_pc = db.unslide(pc)
            if unslide_pc is not None:
                self._decompiler.navigate_to_addr(unslide_pc)

        self._decompiler.refresh_view()
