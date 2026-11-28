use std::{fs::File, hint::black_box};

use criterion::{BatchSize, Bencher, Criterion, criterion_group, criterion_main};
use frinet_db::{db::Db, format::Time, irange::IRange, time_series::TimeSearch};
use rand::{RngExt, rngs::StdRng, seq::IndexedRandom};

criterion_main!(benches);
criterion_group!(benches, criterion_benchmark);

fn criterion_benchmark(c: &mut Criterion) {
    let Ok(path) = std::env::var("BENCH_DB") else {
        eprintln!("warning: BENCH_DB is not set, skipping the benchmarks");
        return;
    };
    let file = File::open(path).expect("failed to open BENCH_DB");
    let mmap = unsafe {
        memmap2::MmapOptions::new()
            .map(&file)
            .expect("failed to mmap BENCH_DB")
    };
    let db = Db::from_aligned_slice(&mmap).unwrap();

    c.bench_function("Memory read 8", |b| read_memory_range::<8>(b, &db));
    c.bench_function("Memory read 64", |b| read_memory_range::<64>(b, &db));
    c.bench_function("Memory read 128", |b| read_memory_range::<128>(b, &db));
    c.bench_function("Memory read 1024", |b| read_memory_range::<1024>(b, &db));
    c.bench_function("Memory read 4096", |b| read_memory_range::<4096>(b, &db));

    c.bench_function("PC prev", |b| pc_prev(b, &db));
    c.bench_function("PC next", |b| pc_next(b, &db));
    c.bench_function("PC first", |b| pc_first(b, &db));
    c.bench_function("PC last", |b| pc_last(b, &db));
    c.bench_function("PC times with", |b| pc_times_with(b, &db));
    c.bench_function("PC distinct values", |b| pc_distinct_values(b, &db));
    c.bench_function("Fetch all registers", |b| fetch_all_registers(b, &db));
    c.bench_function("Writes of all registers", |b| {
        writes_of_all_registers(b, &db)
    });
    c.bench_function("PC values over 11 steps", |b| pc_values_in::<11>(b, &db));
    c.bench_function("PC values over 800 steps", |b| pc_values_in::<800>(b, &db));

    for name in db.metadata.registers.iter().map(|it| &it.name) {
        c.bench_function(&format!("Fetch register: {}", name), |b| {
            fetch_one_register(b, &db, name)
        });
        c.bench_function(&format!("Changes of register: {}", name), |b| {
            changes_of_one_register(b, &db, name)
        });
    }
}

fn read_memory_range<const LEN: usize>(b: &mut Bencher, db: &Db) {
    let mut rng: StdRng = rand::make_rng();

    b.iter_batched(
        || {
            let zone = db.write_zones.choose(&mut rng).unwrap();
            let addr = rng.random_range(zone.bbox.addr.min..zone.bbox.addr.max);
            let time = rng.random_range(zone.bbox.time.min..zone.bbox.time.max);
            (IRange::from_start_len(addr, LEN as _), time)
        },
        |(range, time)| black_box(db).read_memory_with_unknowns(range, time),
        BatchSize::SmallInput,
    );
}

fn pc_prev(b: &mut Bencher, db: &Db) {
    pc_find(b, db, TimeSearch::Before);
}

fn pc_next(b: &mut Bencher, db: &Db) {
    pc_find(b, db, TimeSearch::After);
}

fn pc_first(b: &mut Bencher, db: &Db) {
    pc_find(b, db, |_| TimeSearch::First);
}

fn pc_last(b: &mut Bencher, db: &Db) {
    pc_find(b, db, |_| TimeSearch::Last);
}

/// Search a PC value taken at a random time, from another random time
fn pc_find(b: &mut Bencher, db: &Db, search: impl Fn(Time) -> TimeSearch) {
    let mut rng: StdRng = rand::make_rng();

    let pc = db.pc().unwrap();
    let time_range = pc.time_range().unwrap();

    b.iter_batched(
        || {
            let time = rng.random_range(time_range.min..time_range.max);
            let pc_time = rng.random_range(time_range.min..time_range.max);
            let value = pc.value_at(pc_time).unwrap();
            (search(time), value)
        },
        |(search, value)| black_box(pc).find_time_with(search, value),
        BatchSize::SmallInput,
    );
}

/// Every time the PC held a value it took at a random time
fn pc_times_with(b: &mut Bencher, db: &Db) {
    let mut rng: StdRng = rand::make_rng();

    let pc = db.pc().unwrap();
    let time_range = pc.time_range().unwrap();

    b.iter_batched(
        || {
            let time = rng.random_range(time_range.min..time_range.max);
            pc.value_at(time).unwrap()
        },
        |value| black_box(pc).times_with(value),
        BatchSize::SmallInput,
    );
}

fn pc_distinct_values(b: &mut Bencher, db: &Db) {
    let pc = db.pc().unwrap();
    b.iter(|| black_box(pc).distinct_values());
}

/// What the register view asks for at every time change
fn writes_of_all_registers(b: &mut Bencher, db: &Db) {
    let mut rng: StdRng = rand::make_rng();

    let time_max = trace_time_max(db);

    b.iter_batched(
        || rng.random_range(0..time_max),
        |time| {
            for register in black_box(db.registers()) {
                black_box(register.is_write_at(time));
            }
        },
        BatchSize::SmallInput,
    );
}

fn pc_values_in<const LEN: Time>(b: &mut Bencher, db: &Db) {
    let mut rng: StdRng = rand::make_rng();

    let pc = db.pc().unwrap();
    let time_range = pc.time_range().unwrap();

    b.iter_batched(
        || rng.random_range(time_range.min..time_range.max - LEN),
        |time| {
            black_box(pc)
                .values_in(IRange::new(time, time + LEN - 1))
                .for_each(|value| {
                    black_box(value);
                })
        },
        BatchSize::SmallInput,
    );
}

fn fetch_all_registers(b: &mut Bencher, db: &Db) {
    let mut rng: StdRng = rand::make_rng();

    let time_max = trace_time_max(db);

    b.iter_batched(
        || rng.random_range(0..time_max),
        |time| {
            for register in black_box(db.registers()) {
                black_box(register.value_at(time));
            }
        },
        BatchSize::SmallInput,
    );
}

fn fetch_one_register(b: &mut Bencher, db: &Db, name: &str) {
    let mut rng: StdRng = rand::make_rng();

    let time_max = trace_time_max(db);
    let register = db.register_by_name(name).unwrap();

    b.iter_batched(
        || rng.random_range(0..time_max),
        |time| black_box(register).value_at(time),
        BatchSize::SmallInput,
    );
}

/// A dense series walks the run of identical values around the time
fn changes_of_one_register(b: &mut Bencher, db: &Db, name: &str) {
    let mut rng: StdRng = rand::make_rng();

    let time_max = trace_time_max(db);
    let register = db.register_by_name(name).unwrap();

    b.iter_batched(
        || rng.random_range(0..time_max),
        |time| {
            let register = black_box(register);
            (register.prev_change(time), register.next_change(time))
        },
        BatchSize::SmallInput,
    );
}

fn trace_time_max(db: &Db) -> Time {
    db.registers()
        .iter()
        .filter_map(|register| register.time_range())
        .map(|range| range.max)
        .max()
        .unwrap()
}
