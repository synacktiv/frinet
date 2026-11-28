"""
Generates a readable narrative ("story") of a trace from its call list.

Pure Python (no Qt / IDA), so it can be tested outside IDA. Every point in time
and every address in the text is a link:
    go:<line>:<call address>   move the trace time to that call and show it in IDA
    line:<n>                   move the trace time to line n of the .tenet
    t:<time>                   move the trace time to <time>
    ea:<address>               show an address in IDA (hex, IDA address)

API arguments are read from the trace (x64 Windows calling convention: rcx, rdx,
r8, r9). Strings are decoded when their bytes are in the trace.
Return values of API calls are not shown: with -e the API runs untraced, so
rax after the call is not recorded.
"""
import html
from collections import Counter
from typing import Callable, Optional

from calls_model import CallEvent, CallModel, line_to_time

ARG_REGS = ("rcx", "rdx", "r8", "r9")
MAX_STEPS = 400          # top-level steps written in detail
MAX_STR = 200            # characters shown for a string argument

WM_NAMES = {
    0x000B: "WM_SETREDRAW", 0x000C: "WM_SETTEXT", 0x000D: "WM_GETTEXT",
    0x000E: "WM_GETTEXTLENGTH", 0x0010: "WM_CLOSE", 0x0111: "WM_COMMAND",
    0x0080: "WM_SETICON", 0x0030: "WM_SETFONT", 0x0400: "WM_USER",
    0x00B0: "EM_GETSEL", 0x00B1: "EM_SETSEL", 0x00B8: "EM_GETMODIFY",
    0x00B9: "EM_SETMODIFY", 0x00BA: "EM_GETLINECOUNT", 0x00BD: "EM_GETHANDLE",
    0x00C5: "EM_LIMITTEXT", 0x00C2: "EM_REPLACESEL", 0x00CF: "EM_SETREADONLY",
    0x0401: "SB_SETTEXTA", 0x040B: "SB_SETTEXTW", 0x0404: "SB_SETPARTS",
}
CODE_PAGES = {0: "CP_ACP", 1: "CP_OEMCP", 65001: "UTF-8", 1200: "UTF-16LE", 1252: "Windows-1252"}
HKEYS = {
    0x80000000: "HKEY_CLASSES_ROOT", 0x80000001: "HKEY_CURRENT_USER",
    0x80000002: "HKEY_LOCAL_MACHINE", 0x80000003: "HKEY_USERS",
}

# API name -> (category, template). {n:kind} = argument n formatted as kind.
# kinds: wstr, str, int, hex, ptr, access, cp, wm, hkey, guid, ord
API = {
    # files
    "CreateFileW": ("file", "opens file {0:wstr} ({1:access})"),
    "CreateFileA": ("file", "opens file {0:str} ({1:access})"),
    "CreateFile2": ("file", "opens file {0:wstr} ({1:access})"),
    "ReadFile": ("file", "reads {2:int} bytes from handle {0:hex} into {1:ptr}"),
    "WriteFile": ("file", "writes {2:int} bytes from {1:ptr} to handle {0:hex}{1:preview2}"),
    "CloseHandle": ("file", "closes handle {0:hex}"),
    "SetEndOfFile": ("file", "sets the end of file of handle {0:hex}"),
    "SetFilePointer": ("file", "moves the file pointer of handle {0:hex} to {1:int}"),
    "SetFilePointerEx": ("file", "moves the file pointer of handle {0:hex} to {1:int}"),
    "GetFileSize": ("file", "gets the size of handle {0:hex}"),
    "GetFileSizeEx": ("file", "gets the size of handle {0:hex}"),
    "GetFileAttributesW": ("file", "checks the attributes of {0:wstr}"),
    "GetFileAttributesExW": ("file", "checks the attributes of {0:wstr}"),
    "PathFileExistsW": ("file", "checks whether {0:wstr} exists"),
    "DeleteFileW": ("file", "deletes {0:wstr}"),
    "CopyFileW": ("file", "copies {0:wstr} to {1:wstr}"),
    "MoveFileExW": ("file", "moves {0:wstr} to {1:wstr}"),
    "MoveFileW": ("file", "moves {0:wstr} to {1:wstr}"),
    "CreateDirectoryW": ("file", "creates directory {0:wstr}"),
    "FindFirstFileW": ("file", "searches for {0:wstr}"),
    "FindFirstFileExW": ("file", "searches for {0:wstr}"),
    "GetTempPathW": ("file", "gets the temp folder"),
    "PathFindExtensionW": ("string", "finds the extension of {0:wstr}"),
    "PathFindFileNameW": ("string", "finds the file name in {0:wstr}"),
    "PathCchCombine": ("string", "combines paths {2:wstr} and {3:wstr}"),
    # registry
    "RegOpenKeyExW": ("registry", "opens registry key {0:hkey}\\{1:wstr}"),
    "RegCreateKeyExW": ("registry", "creates registry key {0:hkey}\\{1:wstr}"),
    "RegQueryValueExW": ("registry", "reads registry value {1:wstr}"),
    "RegSetValueExW": ("registry", "writes registry value {1:wstr}"),
    "RegGetValueW": ("registry", "reads registry value {1:wstr}\\{2:wstr}"),
    "RegDeleteValueW": ("registry", "deletes registry value {1:wstr}"),
    "RegCloseKey": ("registry", "closes registry key {0:hex}"),
    # processes and modules
    "CreateProcessW": ("process", "starts process {0:wstr} {1:wstr}"),
    "CreateProcessA": ("process", "starts process {0:str} {1:str}"),
    "ShellExecuteW": ("process", "runs {1:wstr} on {2:wstr}"),
    "ShellExecuteExW": ("process", "runs a shell command"),
    "OpenProcess": ("process", "opens process {2:int}"),
    "TerminateProcess": ("process", "terminates process handle {0:hex}"),
    "CreateThread": ("process", "creates a thread at {2:ptr}"),
    "LoadLibraryW": ("module", "loads {0:wstr}"),
    "LoadLibraryA": ("module", "loads {0:str}"),
    "LoadLibraryExW": ("module", "loads {0:wstr}"),
    "LoadLibraryExA": ("module", "loads {0:str}"),
    "GetModuleHandleW": ("module", "gets module {0:wstr}"),
    "GetModuleHandleExW": ("module", "gets a module handle"),
    "GetProcAddress": ("module", "looks up {1:ord} in module {0:hex}"),
    "ResolveDelayLoadedAPI": ("module", "resolves a delay-loaded function"),
    "FreeLibrary": ("module", "unloads module {0:hex}"),
    # memory
    "VirtualAlloc": ("memory", "allocates {1:int} bytes of virtual memory (protection {3:hex})"),
    "VirtualProtect": ("memory", "changes the protection of {0:ptr} ({1:int} bytes) to {2:hex}"),
    "VirtualFree": ("memory", "frees virtual memory at {0:ptr}"),
    "HeapAlloc": ("memory", "allocates {2:int} bytes on the heap"),
    "HeapReAlloc": ("memory", "reallocates {2:ptr} to {3:int} bytes"),
    "HeapFree": ("memory", "frees heap block {2:ptr}"),
    "LocalAlloc": ("memory", "allocates {1:int} bytes"),
    "LocalReAlloc": ("memory", "reallocates {0:ptr} to {1:int} bytes"),
    "LocalFree": ("memory", "frees {0:ptr}"),
    "LocalLock": ("memory", "locks memory handle {0:hex} (gets a pointer to it)"),
    "LocalUnlock": ("memory", "unlocks memory handle {0:hex}"),
    "LocalSize": ("memory", "gets the size of memory handle {0:hex}"),
    "GlobalAlloc": ("memory", "allocates {1:int} bytes"),
    "GlobalFree": ("memory", "frees {0:ptr}"),
    "GlobalLock": ("memory", "locks memory handle {0:hex}"),
    "GlobalUnlock": ("memory", "unlocks memory handle {0:hex}"),
    "CoTaskMemAlloc": ("memory", "allocates {0:int} bytes (COM)"),
    "CoTaskMemFree": ("memory", "frees {0:ptr} (COM)"),
    "memcpy": ("memory", "copies {2:int} bytes from {1:ptr} to {0:ptr}"),
    "memmove": ("memory", "copies {2:int} bytes from {1:ptr} to {0:ptr}"),
    "memset": ("memory", "fills {2:int} bytes at {0:ptr} with {1:hex}"),
    # strings
    "WideCharToMultiByte": ("string", "converts {3:cnt} UTF-16 characters at {2:ptr} to {0:cp}"),
    "MultiByteToWideChar": ("string", "converts {3:cnt} bytes at {2:ptr} from {0:cp} to UTF-16"),
    "lstrlenW": ("string", "measures {0:wstr}"),
    "wcslen": ("string", "measures {0:wstr}"),
    "lstrcmpiW": ("string", "compares {0:wstr} with {1:wstr}"),
    "CompareStringOrdinal": ("string", "compares {0:wstr} with {2:wstr}"),
    "_wcsicmp": ("string", "compares {0:wstr} with {1:wstr}"),
    "_o__wcsicmp": ("string", "compares {0:wstr} with {1:wstr}"),
    "wcscmp": ("string", "compares {0:wstr} with {1:wstr}"),
    "StringCchPrintfW": ("string", "formats text with {2:wstr}"),
    "wsprintfW": ("string", "formats text with {1:wstr}"),
    # user interface
    "SendMessageW": ("ui", "sends {1:wm} to window {0:hex} (wParam {2:hex}, lParam {3:hex})"),
    "PostMessageW": ("ui", "posts {1:wm} to window {0:hex} (wParam {2:hex}, lParam {3:hex})"),
    "SendMessageA": ("ui", "sends {1:wm} to window {0:hex}"),
    "SetWindowTextW": ("ui", "sets the window text to {1:wstr}"),
    "GetWindowTextW": ("ui", "reads the text of window {0:hex}"),
    "MessageBoxW": ("ui", "shows a message box: {1:wstr} / {2:wstr}"),
    "MessageBoxExW": ("ui", "shows a message box: {1:wstr} / {2:wstr}"),
    "SetCursor": ("ui", "changes the mouse cursor"),
    "LoadCursorW": ("ui", "loads a cursor"),
    "ShowWindow": ("ui", "shows/hides window {0:hex}"),
    "InvalidateRect": ("ui", "asks window {0:hex} to redraw"),
    "UpdateWindow": ("ui", "redraws window {0:hex}"),
    # COM
    "CoCreateInstance": ("com", "creates COM object {0:guid}"),
    "CoInitializeEx": ("com", "initialises COM"),
    "CoUninitialize": ("com", "uninitialises COM"),
    # network
    "connect": ("network", "connects socket {0:hex}"),
    "send": ("network", "sends {2:int} bytes on socket {0:hex}{1:preview2}"),
    "recv": ("network", "receives up to {2:int} bytes on socket {0:hex}"),
    "InternetOpenUrlW": ("network", "opens URL {1:wstr}"),
    "InternetConnectW": ("network", "connects to {1:wstr}"),
    "HttpOpenRequestW": ("network", "prepares HTTP {1:wstr} {2:wstr}"),
    "HttpSendRequestW": ("network", "sends an HTTP request"),
    "WinHttpConnect": ("network", "connects to {1:wstr}"),
    "WinHttpOpenRequest": ("network", "prepares HTTP {1:wstr} {2:wstr}"),
    "URLDownloadToFileW": ("network", "downloads {1:wstr} to {2:wstr}"),
    # crypto
    "CryptEncrypt": ("crypto", "encrypts data"),
    "CryptDecrypt": ("crypto", "decrypts data"),
    "BCryptEncrypt": ("crypto", "encrypts {2:int} bytes"),
    "BCryptDecrypt": ("crypto", "decrypts {2:int} bytes"),
    "BCryptGenRandom": ("crypto", "generates {2:int} random bytes"),
    # errors
    "GetLastError": ("error", "reads the last error code"),
    "SetLastError": ("error", "sets the last error code to {0:hex}"),
}
KEY_CATEGORIES = ("file", "registry", "process", "module", "network", "crypto", "com")
CATEGORY_TITLES = {
    "file": "Files", "registry": "Registry", "process": "Processes and threads",
    "module": "Modules (DLLs)", "network": "Network", "crypto": "Cryptography",
    "com": "COM", "memory": "Memory", "string": "Strings", "ui": "User interface",
    "error": "Errors", "other": "Other APIs",
}
ACCESS = [(0x80000000, "GENERIC_READ"), (0x40000000, "GENERIC_WRITE"),
          (0x20000000, "GENERIC_EXECUTE"), (0x10000000, "GENERIC_ALL")]


class TraceData:
    """What the story needs from the trace. In IDA: from frinet's DB."""

    def reg(self, t: int, name: str) -> Optional[int]:
        return None

    def mem(self, t: int, addr: int, size: int) -> list:
        return [None] * size


class FrinetTraceData(TraceData):
    def __init__(self, db):
        self.db = db
        self._snap_t = None
        self._snap = None

    def reg(self, t, name):
        if self._snap_t != t:
            self._snap = self.db.frinet_db.registers_snapshot(self.db.clamp_time(t))
            self._snap_t = t
        r = self._snap.reg(name)
        return None if r is None else r.value

    def mem(self, t, addr, size):
        try:
            return self.db.memory_bytes_at(self.db.clamp_time(t), addr, size)
        except Exception:
            return [None] * size


def api_short_name(target: str) -> str:
    name = target.split("!", 1)[1] if "!" in target else target
    return name.split("+0x")[0]


def api_lookup(target: str):
    name = api_short_name(target)
    if name in API:
        return API[name]
    for suffix in ("W", "A"):  # unknown A/W variant of a known API
        if name.endswith(suffix) and name[:-1] + "W" in API:
            return API[name[:-1] + "W"]
    return None


# ---------- argument formatting ----------
class Fmt:
    def __init__(self, data: TraceData, t: int):
        self.data, self.t = data, t
        self._regs = [data.reg(t, r) for r in ARG_REGS]

    def arg(self, i: int) -> Optional[int]:
        return self._regs[i] if i < len(self._regs) else None

    def string(self, ptr: Optional[int], wide: bool) -> str:
        if not ptr:
            return "NULL" if ptr == 0 else "(unknown pointer)"
        width = 2 if wide else 1
        raw = self.data.mem(self.t, ptr, MAX_STR * width)
        chars, cut = [], False
        for i in range(0, len(raw) - width + 1, width):
            unit = raw[i:i + width]
            if any(b is None for b in unit):
                cut = True
                break
            code = unit[0] | (unit[1] << 8 if wide else 0)
            if code == 0:
                break
            chars.append(chr(code) if 0x20 <= code < 0xD800 or code in (9,) else "�")
        else:
            cut = True
        if not chars:
            return f"(string at {ptr:#x}, not in trace)"
        return '"' + "".join(chars) + ('…"' if cut else '"')

    def preview(self, ptr: Optional[int], size: Optional[int]) -> str:
        if not ptr or not size:
            return ""
        n = min(size, 32)
        raw = self.data.mem(self.t, ptr, n)
        if all(b is None for b in raw):
            return " (data not in trace)"
        hx = " ".join("??" if b is None else f"{b:02x}" for b in raw)
        txt = "".join("." if b is None or not 0x20 <= b < 0x7F else chr(b) for b in raw)
        return f" — data: `{hx}{' …' if size > n else ''}` \"{txt}\""

    def fmt(self, i: int, kind: str) -> str:
        v = self.arg(i)
        if kind == "wstr":
            return self.string(v, True)
        if kind == "str":
            return self.string(v, False)
        if kind == "preview2":
            return self.preview(v, self.arg(2))
        if v is None:
            return "?"
        if kind == "int":
            return str(v) if v < 0x10000 else f"{v:#x}"
        if kind == "cnt":
            return "all (null-terminated)" if v in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF) else str(v)
        if kind == "ptr":
            return f"`{v:#x}`"
        if kind == "access":
            flags = [n for bit, n in ACCESS if v & bit]
            return "|".join(flags) if flags else f"access {v:#x}"
        if kind == "cp":
            return CODE_PAGES.get(v, f"code page {v}")
        if kind == "wm":
            return WM_NAMES.get(v & 0xFFFF, f"message {v:#x}")
        if kind == "hkey":
            return HKEYS.get(v & 0xFFFFFFFF, f"{v:#x}")
        if kind == "ord":
            return f"ordinal {v}" if v < 0x10000 else self.string(v, False)
        if kind == "guid":
            raw = self.data.mem(self.t, v, 16)
            if any(b is None for b in raw):
                return f"(CLSID at {v:#x})"
            b = bytes(raw)
            return "{%08X-%04X-%04X-%s-%s}" % (
                int.from_bytes(b[0:4], "little"), int.from_bytes(b[4:6], "little"),
                int.from_bytes(b[6:8], "little"), b[8:10].hex().upper(), b[10:16].hex().upper())
        return f"{v:#x}"  # hex

    def render(self, template: str) -> str:
        out, i = [], 0
        while i < len(template):
            j = template.find("{", i)
            if j < 0:
                out.append(template[i:])
                break
            out.append(template[i:j])
            k = template.index("}", j)
            n, kind = template[j + 1:k].split(":")
            out.append(self.fmt(int(n), kind))
            i = k + 1
        return "".join(out)


# ---------- the story ----------
class Block:
    """One paragraph / list item of the story. text is Markdown with links."""

    def __init__(self, kind: str, text: str, line: int = 0, level: int = 0):
        self.kind = kind      # h1 h2 h3 p li
        self.text = text
        self.line = line      # .tenet line this block is about (for sync)
        self.level = level    # list nesting


def L(line: int, site: str = "", label: Optional[str] = None) -> str:
    """Markdown link to a point in time."""
    label = label or f"line {line}"
    href = f"go:{line}:{site}" if site else f"line:{line}"
    return f"[{label}]({href})"


def E(addr: str, label: Optional[str] = None) -> str:
    return f"[{label or addr}](ea:{addr})"


class StoryGenerator:
    def __init__(self, model: CallModel, data: Optional[TraceData] = None,
                 name: Optional[Callable[[CallEvent], str]] = None):
        self.model = model
        self.data = data or TraceData()
        self.name = name or model.display_name
        self.blocks: list[Block] = []
        self.api_counts = Counter()
        self.key_events: dict = {}

    def fn(self, ev: CallEvent) -> str:
        n = self.name(ev)
        ea = self.model.target_ea(ev) if ev.kind != "api" else None
        return f"**[{n}](ea:{ea:X})**" if ea is not None else f"**`{n}`**"

    def describe_api(self, ev: CallEvent) -> tuple[str, str]:
        """(category, sentence) for an API call, with decoded arguments."""
        t = line_to_time(ev.line)
        entry = api_lookup(ev.target)
        name = self.name(ev)
        fmt = Fmt(self.data, t)
        if entry is None:
            args = ", ".join(
                f"{r}={'?' if fmt.arg(i) is None else hex(fmt.arg(i))}" for i, r in enumerate(ARG_REGS))
            return "other", f"calls **{name}**({args})"
        cat, template = entry
        return cat, f"**{name}**: {fmt.render(template)}"

    def run(self) -> list:
        m = self.model
        root = m.root
        n_calls = sum(1 for e in m.events if e.kind == "call")
        n_api = sum(1 for e in m.events if e.kind == "api")
        funcs = {e.target for e in m.events if e.kind == "call"}
        t0, t1 = m.time_range
        for e in m.events:
            if e.kind == "api":
                self.api_counts[self.name(e)] += 1

        self.add("h1", f"Story of {self.fn(root)}", root.line)
        self.add("p", (
            f"The trace covers {L(root.line, label='line ' + str(root.line))} to "
            f"{L(root.end_line, label='line ' + str(root.end_line))} "
            f"(about {t1 - t0:,} instructions). The traced function calls "
            f"{len(funcs)} different functions ({n_calls} calls) and makes {n_api} API calls."
        ), root.line)
        if self.api_counts:
            top = ", ".join(f"{n} ×{c}" for n, c in self.api_counts.most_common(8))
            self.add("p", f"Most used APIs: {top}.", root.line)

        self.collect_key_events(root)
        if self.key_events:
            self.add("h2", "Key events", root.line)
            for cat in KEY_CATEGORIES + ("ui",):
                items = self.key_events.get(cat)
                if not items:
                    continue
                self.add("h3", CATEGORY_TITLES[cat], items[0][0].line)
                for ev, sentence in items[:30]:
                    self.add("li", f"{L(ev.line, ev.site)}: {sentence}", ev.line)
                if len(items) > 30:
                    self.add("li", f"… and {len(items) - 30} more", items[30][0].line)

        self.add("h2", "Step by step", root.line)
        self.steps(root, level=0, budget=[MAX_STEPS])
        return self.blocks

    def add(self, kind, text, line, level=0):
        self.blocks.append(Block(kind, text, line, level))

    def collect_key_events(self, ev: CallEvent) -> None:
        for c in ev.children:
            if c.kind == "api":
                cat, sentence = self.describe_api(c)
                if cat in KEY_CATEGORIES or (cat == "ui" and api_short_name(c.target) in (
                        "SetWindowTextW", "MessageBoxW", "MessageBoxExW")):
                    self.key_events.setdefault(cat, []).append((c, sentence))
            else:
                self.collect_key_events(c)

    def summary_of(self, ev: CallEvent) -> str:
        """Short description of what happens inside a call."""
        apis = Counter()
        sub = 0
        stack = list(ev.children)
        while stack:
            c = stack.pop()
            if c.kind == "api":
                apis[api_short_name(self.name(c))] += 1
            else:
                sub += 1
                stack.extend(c.children)
        parts = []
        if apis:
            parts.append("uses " + ", ".join(
                f"{n}" + (f" ×{k}" if k > 1 else "") for n, k in apis.most_common(6))
                + (" and more" if len(apis) > 6 else ""))
        if sub:
            parts.append(f"{sub} nested call{'s' if sub > 1 else ''}")
        return "; ".join(parts) if parts else "no further calls"

    def steps(self, ev: CallEvent, level: int, budget: list) -> None:
        kids = ev.children
        i = 0
        while i < len(kids):
            if budget[0] <= 0:
                self.add("li", "… (story truncated: trace too large; use the Call tree for the rest)",
                         kids[i].line, level)
                return
            budget[0] -= 1
            c = kids[i]
            if c.kind == "api":
                # group consecutive API calls into one item
                group = [c]
                while i + 1 < len(kids) and kids[i + 1].kind == "api" and len(group) < 8:
                    i += 1
                    group.append(kids[i])
                parts = []
                for g in group:
                    _cat, sentence = self.describe_api(g)
                    parts.append(f"{L(g.line, g.site)} {sentence}")
                self.add("li", "; then ".join(parts) + ".", c.line, level)
            else:
                dur = model_duration(self.model, c)
                end = (f" until {L(c.end_line, label='line ' + str(c.end_line))}"
                       if c.end_line is not None else "")
                self.add("li", (
                    f"{L(c.line, c.site)}: calls {self.fn(c)}{end} "
                    f"({dur:,} instruction{'' if dur == 1 else 's'}) — {self.summary_of(c)}."
                ), c.line, level)
                if level < 2 and c.children:
                    self.steps(c, level + 1, budget)
            i += 1


def model_duration(model: CallModel, ev: CallEvent) -> int:
    return max(0, model.end_time(ev) - model.start_time(ev))


# ---------- rendering ----------
def to_markdown(blocks: list) -> str:
    out = []
    for b in blocks:
        if b.kind == "h1":
            out.append(f"# {b.text}\n")
        elif b.kind == "h2":
            out.append(f"\n## {b.text}\n")
        elif b.kind == "h3":
            out.append(f"\n### {b.text}\n")
        elif b.kind == "li":
            out.append("  " * b.level + f"- {b.text}")
        else:
            out.append(f"\n{b.text}\n")
    return "\n".join(out) + "\n"


def _md_inline_to_html(text: str) -> str:
    """Tiny Markdown subset used by the generator: [label](href), **bold**, `code`."""
    import re

    s = html.escape(text, quote=False)
    s = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>', s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s


def to_html(blocks: list) -> str:
    """HTML with an anchor per block (L<line>) so the view can follow the timeline."""
    out = ['<html><body style="font-family: sans-serif;">']
    open_levels = 0
    for idx, b in enumerate(blocks):
        anchor = f'<a name="b{idx}"></a>'
        if b.kind != "li":
            out.append("</ul>" * open_levels)
            open_levels = 0
        if b.kind in ("h1", "h2", "h3"):
            out.append(f"<{b.kind}>{anchor}{_md_inline_to_html(b.text)}</{b.kind}>")
        elif b.kind == "li":
            while open_levels < b.level + 1:
                out.append("<ul>")
                open_levels += 1
            while open_levels > b.level + 1:
                out.append("</ul>")
                open_levels -= 1
            out.append(f"<li>{anchor}{_md_inline_to_html(b.text)}</li>")
        else:
            out.append(f"<p>{anchor}{_md_inline_to_html(b.text)}</p>")
    out.append("</ul>" * open_levels)
    out.append("</body></html>")
    return "\n".join(out)
