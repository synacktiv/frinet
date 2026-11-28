# Testing, Fuzzing & Benchmark

## Tests

```bash
cargo test
```

## Fuzzing

The fuzz targets (`register`, `memory_writes`, `search`) live in `crates/fuzz`:

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run --fuzz-dir crates/fuzz register
```

## Benchmark

The benchmark queries an existing DB, given by `BENCH_DB`:

```bash
cargo install cargo-criterion
BENCH_DB=my.db cargo criterion
```
