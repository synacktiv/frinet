#!/usr/bin/env python3
"""
Frinet call list (.calls.txt) next to a .tenet trace.

Two ways to get it:
  * trace.py -X <exe>  : built after tracing from the trace + a copy of the traced exe (this file)
  * trace.py (no -X)   : recorded by the tracer itself while tracing (trace_x64.c / trace.js)

Both write the same format:
    line=<n>  <indent><kind> <target>   @<call address>
  line  = line number in the .tenet file (as shown in a text editor)
  kind  = call (into traced code), api (call into an untraced DLL), ret (return)

Standalone use (needs: pip install pefile capstone):
    python calltree.py <exe> <trace.tenet> [out.calls.txt] [function offset]
"""
import os
import re
import sys

HEADER = (
    "# frinet call list for {trace}\n"
    "# line = line number in the .tenet file; call = into traced code, "
    "api = into an untraced DLL, ret = return\n"
)


def format_event(line, depth, kind, frm, to):
    indent = "    " * (int(depth) + 1)
    if kind == "ret":
        return f"line={line:<9}{indent}ret  -> {to}\n"
    return f"line={line:<9}{indent}{kind:<4} {to}   @{frm}\n"


def calls_path(trace_path):
    return re.sub(r"\.tenet$", "", trace_path) + ".calls.txt"


def build_from_exe(exe, trace_path, out_path=None, start_off=None):
    """Build the call list from a trace and a copy of the traced exe (Windows PE, x64)."""
    import pefile
    import capstone

    out_path = out_path or calls_path(trace_path)
    pe = pefile.PE(exe)
    img = pe.get_memory_mapped_image()
    ib = pe.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    imps = {}
    for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = e.dll.decode().rsplit(".", 1)[0]
        for i in e.imports:
            nm = i.name.decode() if i.name else f"Ordinal_{i.ordinal}"
            imps[i.address - ib] = f"{dll}!{nm}"

    cache = {}

    def insn(rva):
        if rva not in cache:
            cache[rva] = next(md.disasm(img[rva:rva + 16], rva), None)
        return cache[rva]

    def name(rva):
        return f"sub_{ib + rva:X}"

    def addr(rva):
        return f"{ib + rva:X}"

    slide = None
    steps = []  # (line number, rva)
    with open(trace_path, "r", newline="") as fd:
        for n, ln in enumerate(fd, 1):
            if ln.startswith("slide="):
                slide = int(ln[6:].split(",")[0], 16)
                continue
            m = re.match(r"rip=(0x[0-9a-fA-F]+)", ln)
            if m and slide is not None:
                steps.append((n, int(m.group(1), 16) - slide))
    if slide is None:
        raise ValueError("trace has no slide= line, cannot map addresses to the exe")

    out = [HEADER.format(trace=os.path.basename(trace_path))]
    first_rva = start_off if start_off is not None else (steps[0][1] if steps else 0)
    out.append(f"line={steps[0][0] if steps else 1:<9}{name(first_rva)}  (traced function)\n")

    stack = []
    for (ln_a, a), (_, b) in zip(steps, steps[1:]):
        if b in stack:  # returned (by ret or through untraced code)
            while stack and stack[-1] != b:
                stack.pop()
            stack.pop()
            out.append(format_event(ln_a, len(stack), "ret", addr(a), addr(b)))
            continue
        i = insn(a)
        if i is None or i.mnemonic != "call":
            continue
        ret_addr = i.address + i.size
        if b == ret_addr:  # call not followed: API / untraced code
            m = re.search(r"\[rip \+ (0x[0-9a-f]+)\]", i.op_str)
            tgt = imps.get(ret_addr + int(m.group(1), 16)) if m else None
            if tgt is None:
                try:
                    tgt = name(int(i.op_str, 16))
                except ValueError:
                    tgt = f"indirect ({i.op_str})"
            out.append(format_event(ln_a, len(stack), "api", addr(a), tgt))
        else:
            out.append(format_event(ln_a, len(stack), "call", addr(a), name(b)))
            stack.append(ret_addr)

    with open(out_path, "w", newline="") as fd:
        fd.writelines(out)
    return out_path


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    exe, trace = sys.argv[1], sys.argv[2]
    outp = sys.argv[3] if len(sys.argv) > 3 else None
    off = int(sys.argv[4], 16) if len(sys.argv) > 4 else None
    print("Written", build_from_exe(exe, trace, outp, off))
