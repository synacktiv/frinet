from collections.abc import Callable
from typing import TypeVar

import ida_kernwin
from frinet import Cancelled, FrinetError, Task

from .qt.QtCore import QObject, QTimer

T = TypeVar("T")

POLL_SECONDS = 0.1


def run_in_wait_box(task: Task[T], title: str) -> T | None:
    """Waits for `task` in a wait box whose Cancel cancels it, None once cancelled"""
    ida_kernwin.show_wait_box(title)
    try:
        while not task.wait(POLL_SECONDS):
            ida_kernwin.replace_wait_box(f"{title}\n{task.progress:.0%}")
            if ida_kernwin.user_cancelled():
                task.cancel()
        return task.result()
    except Cancelled:
        return None
    finally:
        ida_kernwin.hide_wait_box()


def watch(
    parent: QObject,
    task: Task[T],
    on_tick: Callable[[float], None],
    on_end: Callable[[T | None, FrinetError | None], None],
) -> QTimer:
    """Follows `task` without blocking: `on_tick(progress)` while it runs, then `on_end`

    `on_end` gets the result, or what the work raised, `Cancelled` included.
    """
    timer = QTimer(parent)

    def poll() -> None:
        if not task.done:
            on_tick(task.progress)
            return
        timer.stop()
        try:
            result = task.result()
        except FrinetError as error:
            on_end(None, error)
        else:
            on_end(result, None)

    timer.timeout.connect(poll)
    timer.start(int(POLL_SECONDS * 1000))
    poll()
    return timer
