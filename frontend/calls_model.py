"""
Shared call-list model for the Call tree, Story and Graph windows.

A .calls.txt (written by trace.py / calltree.py) is parsed once into a tree of
CallEvent. The model also knows:
  * how a .tenet line number maps to frinet's trace time
  * which calls are active at a given time (for timeline synchronisation)
  * how to display names: "address" (sub_14000E424) or "real" (current IDA name,
    e.g. from PDB symbols or your own renames)
"""
import bisect
import re
from typing import Callable, Optional

LINE_RE = re.compile(r"^line=(\d+)")
EVENT_RE = re.compile(r"^(call|api|ret)\s+(.*?)\s*$")

NAMES_ADDRESS = "address"
NAMES_REAL = "real"


class CallEvent:
    def __init__(self, line: int, depth: int, kind: str, target: str, site: str):
        self.line = line        # line number in the .tenet file
        self.depth = depth
        self.kind = kind        # call | api | root
        self.target = target    # function / API name or address, as in the file
        self.site = site        # address of the call instruction
        self.end_line: Optional[int] = None  # line of the matching return
        self.children: list["CallEvent"] = []
        self.parent: Optional["CallEvent"] = None

    def __repr__(self):
        return f"<{self.kind} {self.target} line={self.line}>"


def parse_calls_file(path: str) -> CallEvent:
    """Parse a .calls.txt file into a tree of CallEvent (returns the root)."""
    root = CallEvent(0, -1, "root", "trace", "")
    stack = [root]  # stack[d + 1] = open call at depth d
    last_line = 0

    with open(path, "r", encoding="utf-8", errors="replace") as fd:
        for raw in fd:
            raw = raw.rstrip("\r\n")
            if not raw or raw.startswith("#"):
                continue
            m = LINE_RE.match(raw)
            if not m:
                text = raw.strip()  # header "   <function>  (traced function)"
                if text:
                    root.target = text.replace("(traced function)", "").strip()
                continue

            line = int(m.group(1))
            last_line = max(last_line, line)
            digits = m.group(1)
            body = raw[5 + max(9, len(digits)):]
            indent = len(body) - len(body.lstrip(" "))
            depth = max(0, indent // 4 - 1)
            body = body.strip()

            if "(traced function)" in body:
                root.target = body.replace("(traced function)", "").strip()
                root.line = line
                continue

            em = EVENT_RE.match(body)
            if not em:
                continue
            kind, rest = em.group(1), em.group(2)

            while len(stack) > depth + 1:  # close calls deeper than this event
                done = stack.pop()
                if done.end_line is None:
                    done.end_line = line

            if kind == "ret":
                continue

            if "   @" in rest:
                target, site = rest.rsplit("   @", 1)
            else:
                target, site = rest, ""
            ev = CallEvent(line, depth, kind, target.strip(), site.strip())
            ev.parent = stack[-1]
            stack[-1].children.append(ev)
            if kind == "call":
                stack.append(ev)
    root.end_line = last_line + 1
    return root


def line_to_time(line: int) -> int:
    """.tenet line n (1-based, line 1 = slide=) ~ frinet time n-1."""
    return line - 1


class CallModel:
    """One loaded call list, shared by all windows that show it."""

    def __init__(self, path: str, ctx=None):
        self.path = path
        self.ctx = ctx
        self.root = parse_calls_file(path)
        if not self.root.line:
            first = self.root.children[0].line if self.root.children else 1
            self.root.line = max(1, first - 1)
        self.name_mode = NAMES_REAL
        self._name_cache: dict = {}
        self._listeners: list[Callable[[], None]] = []
        self.events: list[CallEvent] = []  # every call/api, in time order
        self._collect(self.root)

    def _collect(self, ev: CallEvent) -> None:
        for c in ev.children:
            self.events.append(c)
            self._collect(c)

    # ---------- time ----------
    def start_time(self, ev: CallEvent) -> int:
        return line_to_time(ev.line)

    def end_time(self, ev: CallEvent) -> int:
        if ev.kind == "api":
            return self.start_time(ev) + 1
        end = ev.end_line if ev.end_line is not None else self.root.end_line
        return line_to_time(end)

    @property
    def time_range(self) -> tuple[int, int]:
        return self.start_time(self.root), self.end_time(self.root)

    def active_path(self, t: int) -> list:
        """Chain of events (root .. deepest) active at trace time t."""
        path = [self.root]
        node = self.root
        while node.children:
            kids = node.children
            starts = [self.start_time(k) for k in kids]
            i = bisect.bisect_right(starts, t) - 1
            nxt = None
            while i >= 0:
                k = kids[i]
                if k.kind == "api":
                    if starts[i] == t:  # exactly on the API call
                        nxt = k
                        break
                    i -= 1
                    continue
                if starts[i] <= t <= self.end_time(k):
                    nxt = k
                break
            if nxt is None:
                break
            path.append(nxt)
            if nxt.kind == "api":
                break
            node = nxt
        return path

    # ---------- names ----------
    def add_listener(self, fn: Callable[[], None]) -> None:
        self._listeners.append(fn)

    def remove_listener(self, fn: Callable[[], None]) -> None:
        if fn in self._listeners:
            self._listeners.remove(fn)

    def _notify(self) -> None:
        for fn in list(self._listeners):
            try:
                fn()
            except RuntimeError:  # widget already deleted
                self.remove_listener(fn)
            except Exception as err:
                print("[frinet]", err)

    def set_name_mode(self, mode: str) -> None:
        if mode != self.name_mode:
            self.name_mode = mode
            self._notify()

    def names_changed(self) -> None:
        """Called when names change in IDA (rename): refresh every view."""
        self._name_cache.clear()
        self._notify()

    def target_ea(self, ev: CallEvent) -> Optional[int]:
        return resolve_name(ev.target, self.ctx)

    def site_ea(self, ev: CallEvent) -> Optional[int]:
        return resolve_addr(ev.site, self.ctx) if ev.site else None

    def display_name(self, ev: CallEvent) -> str:
        return self.name_of(ev.target, api=(ev.kind == "api"))

    def name_of(self, target: str, api: bool = False) -> str:
        key = (self.name_mode, target, api)
        if key not in self._name_cache:
            self._name_cache[key] = self._compute_name(target, api)
        return self._name_cache[key]

    def _compute_name(self, target: str, api: bool) -> str:
        if api:
            # APIs keep their names; strip the api-set prefix in "real" mode
            if self.name_mode == NAMES_REAL and "!" in target:
                dll, func = target.split("!", 1)
                if dll.lower().startswith(("api-ms-win-", "ext-ms-win-")):
                    return func
                return f"{dll}!{func}"
            return target
        ea = resolve_name(target, self.ctx)
        if ea is None:
            return target
        if self.name_mode == NAMES_ADDRESS:
            return f"sub_{ea:X}"
        return ida_name_at(ea) or target


# ---------- IDA helpers (imported lazily so the model can be tested outside IDA) ----------
def ida_name_at(ea: int) -> Optional[str]:
    """Current IDA name of the function at ea (demangled, short form)."""
    try:
        import ida_funcs
        import ida_name
    except ImportError:
        return None
    func = ida_funcs.get_func(ea)
    start = func.start_ea if func is not None else ea
    name = ida_name.get_short_name(start) or ida_name.get_name(start)
    if not name:
        return None
    if start != ea:
        name += f"+0x{ea - start:X}"
    return name


def resolve_addr(text: str, ctx=None) -> Optional[int]:
    """'14000E629' (IDA address) or '0x7ff7...' (runtime address) -> IDA ea."""
    import ida_bytes
    import ida_nalt

    text = text.strip()
    if not text:
        return None
    try:
        val = int(text, 16)
    except ValueError:
        return resolve_name(text, ctx)
    if ida_bytes.is_mapped(val):
        return val
    if ctx is not None and ctx.has_db():  # runtime address -> IDA
        off = ctx.db.unslide(val)
        if off is not None:
            for ea in (off, off + ida_nalt.get_imagebase()):
                if ida_bytes.is_mapped(ea):
                    return ea
    return None


def resolve_name(text: str, ctx=None) -> Optional[int]:
    """sub_14000E424 / KERNEL32!CreateFileW / mod!func / mod+0x1234 -> IDA ea."""
    import ida_bytes
    import ida_idaapi
    import ida_name
    import ida_nalt

    text = text.strip()
    if text.startswith("[API] "):
        text = text[6:]

    m = re.match(r"^sub_([0-9A-Fa-f]+)$", text)
    if m:
        return int(m.group(1), 16)

    m = re.match(r"^(.+?)\+0x([0-9A-Fa-f]+)$", text)  # module+offset
    if m and "!" not in m.group(1):
        off = int(m.group(2), 16)
        for ea in (ida_nalt.get_imagebase() + off, off):
            if ida_bytes.is_mapped(ea):
                return ea
        return None

    if re.match(r"^(0x)?[0-9A-Fa-f]+$", text):
        return resolve_addr(text, ctx)

    func = text.split("!", 1)[1] if "!" in text else text
    plus = 0
    m = re.match(r"^(.*)\+0x([0-9A-Fa-f]+)$", func)
    if m:
        func, plus = m.group(1), int(m.group(2), 16)
    for cand in (func, "__imp_" + func, "_" + func):  # function, IAT entry
        ea = ida_name.get_name_ea(ida_idaapi.BADADDR, cand)
        if ea != ida_idaapi.BADADDR:
            return ea + plus
    return None
