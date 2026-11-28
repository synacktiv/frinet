# Frida tracer

Traces a function of a live process with Frida's Stalker, until it returns. The per-instruction work
is done in a CModule (`common.c` plus `x64.c` or `arm64.c`), the agent (`agent.js`) starts and stops
Stalker, `tracer.py` writes the trace files in `traces/`.

```bash
pip install frida frida-tools
python3 tracer.py -t ls -s 'ls!0x4c00' -f /bin/ls     # spawn
python3 tracer.py -t libfoo.so -s foo_init -p 1234     # attach
frinet index traces/ls_<timestamp>_<tid>_0.trace ls.db
```

| Option                   | Description                                                        |
| ------------------------ | ------------------------------------------------------------------ |
| `--start START`          | `symbol`, `module!symbol`, `module!0xoffset` or `0xabsolute`       |
| `--traced-module MODULE` | Only trace this module, repeat for several (default: every module) |
| `--multi-run`            | Trace every call (one file per call) instead of only the first one |

Plus the usual Frida target options (`-f`, `-p`, `-n`, `-U`, `-D`...).

## Limitations

- The first instructions of the start function are not traced: `Interceptor` relocates them into a
  trampoline (16 bytes on arm64). Their effect shows in the registers of the first step.
- x64: the `xmm` registers are not recorded, and the memory accesses of a few instructions are
  approximated (see the `TODO`s in `x64.c`).
