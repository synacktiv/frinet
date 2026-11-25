# Frinet

> By combining Frida with an enhanced version of Tenet, Frinet facilitates the study of large programs, vulnerability research and root-cause analysis on iOS, Android, Linux, Windows, and most architectures. [Blogpost on the Synacktiv website](https://www.synacktiv.com/publications/frinet-reverse-engineering-made-easier)

<p align="center">
<img alt="Tenet" src="screenshots/frinet.png"/>
</p>

This version is a complete rewrite of `synacktiv/frinet` (originally a fork of [gaasedelen/tenet](https://github.com/synacktiv/frinet/tree/legacy)).
You can still find the old version on the [legacy branch](https://github.com/synacktiv/frinet/tree/legacy).

This project was presented at SSTIC 2026 (in French) : [video/slides/paper](https://www.sstic.org/2026/presentation/spatial_frinet/).

The new archictecture is based on four components :
- `Indexer` : A Rust CLI that produces an optimized index from a trace file.
- `Backend` : A Rust crate that implements specialized algorihms to query the optimized index file.
- `Backend (Python bindings)` : A Rust crate that exposes a python interface.
- `IDA Plugin` : A thin layer of python code that queries and integrates data from the backend into the IDA interface.

## Features

**Tracer based on Frida**: Identical to the legacy version of Frinet.

**Indexer / Backend**:
- Efficient indexing of traces with up to 2 billion instructions (~100 GB).
- Independent of the trace format (only the Tenet format is supported for now).
- Multi-threaded memory search with full regex support.
- Usable as a standalone Rust library: `crates/db`.

**Frontend**: 
- Timeline / Register / Memory views.
- Assembly timeline trails (red/green/blue).
- Memory read/write breakpoint.
- Jump to first/prev/next/last execution.

### Missing features & TODOs

- Reach frontend feature parity with Frinet v1:
  - The call tree view is not yet implemented.
- UI polishing.
  
## Build & Installation

```bash
# Build the Python bindings shared lib
apt install python3-dev
cargo build --release
cp target/release/libfrinet_db.so frontend/frinet_db.so

# Symlink (or copy) the IDA Plugin
ln -s $PWD/frontend ~/.idapro/plugins/frinet
```

## Usage

```bash
# 1. Trace /bin/ls with frida
python tracer/trace.py spawn /bin/ls ls 0x4c00

# 2. Build an optimised index of the trace
cargo run --bin frinet --release -- index --format tenet tracer/traces/ls_xxxx.tenet ls.db

# 3. Open the trace in IDA (File > Load File > Open Frinet DB...)
```

### Tracing a process started by another program

Some programs are only meant to be launched by another process (a launcher, an IDE plugin, a service...) and cannot be spawned on their own. The `child` mode attaches to the parent with Frida child gating, catches the target suspended as soon as the parent starts it, installs the hook and resumes it, so even startup code is traced:

```bash
# Wait for bds.exe to start PexRunner64.exe, then trace PexRunner64.exe+0x2E41C0
python tracer/trace.py child bds.exe PexRunner64.exe 0x2E41C0

# If the hooked module is not the child executable itself, name the child with -c
python tracer/trace.py -c launcher_child.exe child launcher.exe mylib.dll 0x1234
```

Other children started by the parent while waiting are resumed untouched.

## Testing & Fuzzing & Benchmark

```bash
cargo test

cargo install cargo-fuzz
cargo +nightly fuzz run --fuzz-dir crates/fuzz register_indexing

cargo install cargo-criterion
BENCH_DB=my.db cargo criterion
```