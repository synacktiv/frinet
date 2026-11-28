//! Register queries of an indexed trace against a brute force replay of its writes

#![no_main]

use arbitrary::Arbitrary;
use frinet_db::format::Time;
use frinet_db::{
    db::{Db, RegisterInfo},
    irange::IRange,
    scalar::{Scalar, ScalarSize},
    time_series::{CHUNK_LOG2, TimeSearch},
};
use frinet_index::{
    build_index,
    parser::{RawEvent, StaticEventList, TimedRawEvent, TraceHeader},
    storage::VecStorage,
};
use libfuzzer_sys::fuzz_target;

/// One register per width, the last one wider than a machine word
const REGISTERS: [(&str, ScalarSize); 4] = [
    ("r8", ScalarSize::U8),
    ("r32", ScalarSize::U32),
    ("r64", ScalarSize::U64),
    ("r128", ScalarSize::U128),
];

/// Only the first register has a by value index, see [frinet_db::register::PC_REGISTER_IDX]
const INDEXED_BY_VALUE: usize = 0;

/// Keeps the replay below cheap
const MAX_WRITES: usize = 128;
const MAX_SEARCHED: usize = 4;

// 1. Input

#[derive(Arbitrary, Debug)]
struct Input {
    writes: Vec<Write>,
    /// Values looked up through the by value index
    searched: Vec<u8>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct Write {
    /// A `u16` spreads a trace over several chunks of the by time series on its own, so no
    /// stride is needed to reach a chunk boundary
    time: u16,
    reg: u8,
    value: u128,
}

// 2. The trace built from the input

/// A write as the index stores it, the value already truncated to the register width
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegWrite {
    time: Time,
    reg: usize,
    value: u128,
}

struct Trace {
    /// The writes the index keeps, one per register and time, in time order
    writes: Vec<RegWrite>,
    time_end: Time,
    storage: VecStorage,
}

fn build(input: &Input) -> Trace {
    let mut writes: Vec<RegWrite> = input
        .writes
        .iter()
        .take(MAX_WRITES)
        .map(|write| {
            let reg = usize::from(write.reg) % REGISTERS.len();
            RegWrite {
                time: Time::from(write.time),
                reg,
                value: truncate(write.value, REGISTERS[reg].1),
            }
        })
        .collect();

    // the indexer asserts non decreasing times, and a stable sort leaves the writes sharing a
    // time in input order, which is the order it resolves them in
    writes.sort_by_key(|write| write.time);
    let writes = last_write_wins(&writes);

    // the trace ends on its last event
    let time_end = writes.last().map_or(0, |write| write.time);

    let values: Vec<[u8; 16]> = writes
        .iter()
        .map(|write| write.value.to_le_bytes())
        .collect();
    let events: Vec<RawEvent<'_>> = writes
        .iter()
        .zip(&values)
        .map(|(write, value)| RawEvent {
            time: write.time,
            event: TimedRawEvent::Register {
                idx: write.reg,
                bytes: Scalar(&value[..width(write.reg)]),
            },
        })
        .collect();

    let header = TraceHeader {
        registers: REGISTERS
            .iter()
            .map(|(name, scalar_size)| RegisterInfo {
                name: (*name).into(),
                scalar_size: *scalar_size,
            })
            .collect(),
        modules: Vec::new(),
    };

    let mut parser = StaticEventList {
        header: &header,
        events: &events,
    };
    let mut storage = VecStorage::new();
    build_index(&mut parser, &mut (), &mut storage, 2).unwrap();

    Trace {
        writes,
        time_end,
        storage,
    }
}

/// At one time the indexer keeps the last write of a register and drops the ones it shadows
fn last_write_wins(writes: &[RegWrite]) -> Vec<RegWrite> {
    let mut kept: Vec<RegWrite> = Vec::new();

    for write in writes {
        match kept
            .iter_mut()
            .find(|kept| kept.time == write.time && kept.reg == write.reg)
        {
            Some(shadowed) => *shadowed = *write,
            None => kept.push(*write),
        }
    }

    kept
}

fn truncate(value: u128, size: ScalarSize) -> u128 {
    match size.bytes() {
        16 => value,
        bytes => value & ((1u128 << (bytes * 8)) - 1),
    }
}

fn width(reg: usize) -> usize {
    REGISTERS[reg].1.bytes()
}

// 3. The oracle

impl Trace {
    fn db(&self) -> Db<'_> {
        Db::from_aligned_slice(self.storage.as_bytes()).unwrap()
    }

    fn writes_of(&self, reg: usize) -> impl DoubleEndedIterator<Item = &RegWrite> {
        self.writes.iter().filter(move |write| write.reg == reg)
    }

    fn times_of(&self, reg: usize) -> impl DoubleEndedIterator<Item = Time> {
        self.writes_of(reg).map(|write| write.time)
    }

    /// The write holding at `time`: the last one at or before it, none past the trace
    fn holding(&self, reg: usize, time: Time) -> Option<&RegWrite> {
        if time > self.time_end {
            return None;
        }
        self.writes_of(reg).rev().find(|write| write.time <= time)
    }

    fn value_at(&self, reg: usize, time: Time) -> Option<u128> {
        Some(self.holding(reg, time)?.value)
    }

    fn is_write_at(&self, reg: usize, time: Time) -> bool {
        self.times_of(reg).any(|write| write == time)
    }

    /// The step before the write holding at `time`, where the value it replaced ended
    fn prev_change(&self, reg: usize, time: Time) -> Option<Time> {
        self.holding(reg, time)?.time.checked_sub(1)
    }

    /// The next write, which is the first one past `time` whether or not one holds at `time`:
    /// if none holds, every write of the register is already past it
    fn next_change(&self, reg: usize, time: Time) -> Option<Time> {
        if time > self.time_end {
            return None;
        }
        self.times_of(reg).find(|write| *write > time)
    }

    /// First write ..= end of the trace, none if the register is never written
    fn time_range(&self, reg: usize) -> Option<IRange<Time>> {
        Some(IRange::new(self.times_of(reg).next()?, self.time_end))
    }

    fn times_with(&self, reg: usize, value: u128) -> Vec<Time> {
        self.writes_of(reg)
            .filter(|write| write.value == value)
            .map(|write| write.time)
            .collect()
    }

    fn distinct_values(&self, reg: usize) -> Vec<u128> {
        let mut values: Vec<u128> = self.writes_of(reg).map(|write| write.value).collect();
        values.sort_unstable();
        values.dedup();
        values
    }
}

/// Around every write, around every chunk boundary, and past the end of the trace
fn probes(trace: &Trace) -> Vec<Time> {
    let mut times = vec![0, trace.time_end, trace.time_end + 1, trace.time_end + 100];

    let boundaries = (0..=(trace.time_end >> CHUNK_LOG2) + 1).map(|chunk| chunk << CHUNK_LOG2);
    for time in trace
        .writes
        .iter()
        .map(|write| write.time)
        .chain(boundaries)
    {
        times.extend([time.saturating_sub(1), time, time + 1]);
    }

    times.sort_unstable();
    times.dedup();
    times
}

fn scalar_of(reg: usize, value: u128) -> [u8; 16] {
    assert_eq!(truncate(value, REGISTERS[reg].1), value);
    value.to_le_bytes()
}

// 4. The comparison

fuzz_target!(|input: Input| {
    let trace = build(&input);
    let db = trace.db();
    let probes = probes(&trace);

    for (reg, (name, scalar_size)) in REGISTERS.iter().enumerate() {
        let register = db.register_by_name(name).expect("a register of the header");
        assert_eq!(register.scalar_size, *scalar_size, "{name}.scalar_size");
        assert_eq!(
            register.time_range(),
            trace.time_range(reg),
            "{name}.time_range()"
        );

        for &time in &probes {
            let expected = trace.value_at(reg, time).map(|value| scalar_of(reg, value));
            assert_eq!(
                register.value_at(time),
                expected.as_ref().map(|bytes| Scalar(&bytes[..width(reg)])),
                "{name}.value_at({time})"
            );
            assert_eq!(
                register.is_write_at(time),
                trace.is_write_at(reg, time),
                "{name}.is_write_at({time})"
            );
            assert_eq!(
                register.prev_change(time),
                trace.prev_change(reg, time),
                "{name}.prev_change({time})"
            );
            assert_eq!(
                register.next_change(time),
                trace.next_change(reg, time),
                "{name}.next_change({time})"
            );
        }
    }

    // the by value index, on the only register that has one
    let indexed = db.register_by_index(INDEXED_BY_VALUE).unwrap();
    let name = REGISTERS[INDEXED_BY_VALUE].0;
    let is_written = trace.times_of(INDEXED_BY_VALUE).next().is_some();

    if is_written {
        assert!(indexed.has_by_value_index(), "{name} is written");

        let distinct: Vec<u128> = indexed
            .distinct_values()
            .expect("a by value index")
            .iter()
            .map(|value| u128::from(value.try_into_u64().expect("a byte wide scalar")))
            .collect();
        assert_eq!(
            distinct,
            trace.distinct_values(INDEXED_BY_VALUE),
            "every value {name} held, sorted"
        );

        let counts: Vec<u64> = indexed.value_counts().unwrap().collect();
        let expected_counts: Vec<u64> = distinct
            .iter()
            .map(|value| trace.times_with(INDEXED_BY_VALUE, *value).len() as u64)
            .collect();
        assert_eq!(counts, expected_counts, "write count of each value");
    }

    // without a write there is no index to query, so nothing to compare against
    for &searched in input
        .searched
        .iter()
        .take(MAX_SEARCHED)
        .filter(|_| is_written)
    {
        let value = u128::from(searched);
        let scalar = Scalar(&[searched]);
        let expected = trace.times_with(INDEXED_BY_VALUE, value);

        assert_eq!(
            indexed.times_with(scalar).unwrap(),
            expected,
            "{name}.times_with({searched})"
        );

        let find = |search| indexed.find_time_with(search, scalar).unwrap();
        assert_eq!(find(TimeSearch::First), expected.first().copied(), "first");
        assert_eq!(find(TimeSearch::Last), expected.last().copied(), "last");

        for &time in &probes {
            assert_eq!(
                find(TimeSearch::After(time)),
                expected.iter().copied().find(|write| *write > time),
                "{name}.next_time({time}, {searched})"
            );
            assert_eq!(
                find(TimeSearch::Before(time)),
                expected.iter().copied().rev().find(|write| *write < time),
                "{name}.prev_time({time}, {searched})"
            );
        }
    }
});
