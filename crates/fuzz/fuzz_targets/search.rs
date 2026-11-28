#![no_main]

use arbitrary::Arbitrary;
use frinet_db::{
    db::{Db, RegisterInfo},
    format::{Addr, Time},
    scalar::{Scalar, ScalarSize},
    search::{Pattern, SearchMatch, search_pattern},
    task::Task,
};
use frinet_index::{
    build_index,
    parser::{MemoryMode, RawEvent, StaticEventList, TimedRawEvent, TraceHeader},
    storage::VecStorage,
};
use libfuzzer_sys::fuzz_target;

/// Letters, so a needle reads the same as a literal and as a regex
const ALPHABET: [u8; 3] = [b'A', b'B', b'C'];

/// Far enough apart that no match spans both
const CLUSTERS: [Addr; 2] = [0x1000, 0xdead_0000_0000];

/// Narrow, so writes overwrite each other and a search has to chain partial matches across
/// neighbouring leaves
const CLUSTER_SPAN: Addr = 32;

const MAX_WRITES: usize = 32;
const MAX_DATA: usize = 8;

/// Addresses a write can reach inside a cluster
const SCANNED: usize = CLUSTER_SPAN as usize + MAX_DATA;

// What is searched

enum Kind {
    Literal(&'static [u8]),
    Regex(&'static str),
}

/// A needle, and the rule telling whether it holds at a position
///
/// `len` is fixed: the engine accepts on the first accepting state it reaches, so a match is
/// the shortest one, and a needle whose shortest match varies in length would have no single
/// expected `addr_max`. `A{2,3}` is in the table for that reason: its shortest match is the
/// two bytes of `AA`, even though the pattern admits three.
struct Needle {
    kind: Kind,
    len: usize,
    holds: fn(&[Option<u8>]) -> bool,
}

/// One topology each: a single byte, a self overlapping literal, a literal long enough to
/// straddle two leaves, a class, a negated class, an alternation, and a bounded repetition
const NEEDLES: [Needle; 7] = [
    Needle {
        kind: Kind::Literal(b"A"),
        len: 1,
        holds: |w| equals(w, b"A"),
    },
    Needle {
        kind: Kind::Literal(b"AA"),
        len: 2,
        holds: |w| equals(w, b"AA"),
    },
    Needle {
        kind: Kind::Literal(b"ABC"),
        len: 3,
        holds: |w| equals(w, b"ABC"),
    },
    Needle {
        kind: Kind::Regex("A[BC]"),
        len: 2,
        holds: |w| equals(&w[..1], b"A") && in_set(w[1], b"BC"),
    },
    Needle {
        kind: Kind::Regex("[^A]B"),
        len: 2,
        holds: |w| known_other_than(w[0], b'A') && equals(&w[1..], b"B"),
    },
    Needle {
        kind: Kind::Regex("(?:AB|CA)B"),
        len: 3,
        holds: |w| (equals(&w[..2], b"AB") || equals(&w[..2], b"CA")) && equals(&w[2..], b"B"),
    },
    Needle {
        kind: Kind::Regex("A{2,3}"),
        len: 2,
        holds: |w| equals(w, b"AA"),
    },
];

/// Every byte of `window` is known and equal to `bytes`
const fn equals(window: &[Option<u8>], bytes: &[u8]) -> bool {
    if window.len() != bytes.len() {
        return false;
    }
    let mut idx = 0;
    while idx < bytes.len() {
        match window[idx] {
            Some(byte) if byte == bytes[idx] => idx += 1,
            _ => return false,
        }
    }
    true
}

const fn in_set(byte: Option<u8>, set: &[u8]) -> bool {
    let Some(byte) = byte else { return false };
    let mut idx = 0;
    while idx < set.len() {
        if set[idx] == byte {
            return true;
        }
        idx += 1;
    }
    false
}

const fn known_other_than(byte: Option<u8>, excluded: u8) -> bool {
    match byte {
        Some(byte) => byte != excluded,
        None => false,
    }
}

impl Needle {
    fn pattern(&self) -> Pattern {
        match self.kind {
            Kind::Literal(bytes) => Pattern::literal(bytes),
            Kind::Regex(regex) => Pattern::parse(regex),
        }
        .expect("a supported pattern")
    }

    fn label(&self) -> String {
        match self.kind {
            Kind::Literal(bytes) => format!("literal {:?}", String::from_utf8_lossy(bytes)),
            Kind::Regex(regex) => format!("regex {regex:?}"),
        }
    }
}

// 1. Input

#[derive(Arbitrary, Debug)]
struct Input {
    writes: Vec<Write>,
    /// Steps after the last write: a match never overwritten lasts until there
    tail: u8,
}

#[derive(Arbitrary, Debug)]
struct Write {
    time: u8,
    cluster: u8,
    offset: u8,
    data: Vec<u8>,
}

fn addr_of(cluster: u8, offset: u8) -> Addr {
    CLUSTERS[usize::from(cluster) % CLUSTERS.len()] + Addr::from(offset) % CLUSTER_SPAN
}

fn symbol(byte: u8) -> u8 {
    ALPHABET[usize::from(byte) % ALPHABET.len()]
}

// 2. The trace built from the input

#[derive(Debug, Clone)]
struct MemWrite {
    time: Time,
    addr: Addr,
    data: Vec<u8>,
}

struct Trace {
    writes: Vec<MemWrite>,
    time_end: Time,
    storage: VecStorage,
}

fn build(input: &Input) -> Trace {
    let mut writes: Vec<MemWrite> = input
        .writes
        .iter()
        .filter(|write| !write.data.is_empty())
        .take(MAX_WRITES)
        .map(|write| MemWrite {
            time: Time::from(write.time),
            addr: addr_of(write.cluster, write.offset),
            data: write
                .data
                .iter()
                .take(MAX_DATA)
                .map(|byte| symbol(*byte))
                .collect(),
        })
        .collect();

    // the indexer asserts non decreasing times, a stable sort keeps the ties in input order
    writes.sort_by_key(|write| write.time);

    let last_write = writes.last().map_or(0, |write| write.time);
    let time_end = last_write + Time::from(input.tail);

    let tail_value = 0u64.to_le_bytes();
    let mut events: Vec<RawEvent<'_>> = writes
        .iter()
        .map(|write| RawEvent {
            time: write.time,
            event: TimedRawEvent::Memory {
                addr: write.addr,
                bytes: &write.data,
                mode: MemoryMode::Write,
            },
        })
        .collect();
    // the trace ends on its last event
    events.push(RawEvent {
        time: time_end,
        event: TimedRawEvent::Register {
            idx: 0,
            bytes: Scalar(&tail_value),
        },
    });

    let header = TraceHeader {
        registers: vec![RegisterInfo {
            name: "pc".into(),
            scalar_size: ScalarSize::U64,
        }],
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

// 3. The oracle

impl Trace {
    fn db(&self) -> Db<'_> {
        Db::from_aligned_slice(self.storage.as_bytes()).unwrap()
    }

    /// `snapshots[time][offset]`, [None] for a byte no write has revealed yet
    fn snapshots(&self, base: Addr) -> Vec<Vec<Option<u8>>> {
        let mut memory: Vec<Option<u8>> = vec![None; SCANNED];
        let mut per_time = Vec::with_capacity(self.time_end as usize + 1);

        for time in 0..=self.time_end {
            for write in self.writes.iter().filter(|write| write.time == time) {
                for (offset, byte) in write.data.iter().enumerate() {
                    let written = write.addr + offset as Addr;
                    if let Some(idx) = written
                        .checked_sub(base)
                        .filter(|idx| *idx < SCANNED as Addr)
                    {
                        memory[idx as usize] = Some(*byte);
                    }
                }
            }
            per_time.push(memory.clone());
        }

        per_time
    }

    /// The maximal runs of consecutive steps holding `needle`, at every scanned address
    fn expected_matches(
        &self,
        snapshots: &[Vec<Vec<Option<u8>>>],
        needle: &Needle,
    ) -> Vec<SearchMatch> {
        let mut found = Vec::new();

        for (base, snapshots) in CLUSTERS.iter().zip(snapshots) {
            for offset in 0..=SCANNED - needle.len {
                let holds = |time: Time| {
                    let window = &snapshots[time as usize][offset..offset + needle.len];
                    (needle.holds)(window)
                };

                let addr_min = base + offset as Addr;
                let mut run_start: Option<Time> = None;

                for time in 0..=self.time_end {
                    match (holds(time), run_start) {
                        (true, None) => run_start = Some(time),
                        (false, Some(time_min)) => {
                            found.push(found_at(addr_min, needle, time_min, time - 1));
                            run_start = None;
                        }
                        _ => {}
                    }
                }

                if let Some(time_min) = run_start {
                    found.push(found_at(addr_min, needle, time_min, self.time_end));
                }
            }
        }

        found
    }
}

fn found_at(addr_min: Addr, needle: &Needle, time_min: Time, time_max: Time) -> SearchMatch {
    SearchMatch {
        addr_min,
        addr_max: addr_min + needle.len as Addr - 1,
        time_min,
        time_max,
    }
}

/// One occurrence per address and time interval
///
/// The index closes a content leaf on every write, including one rewriting the same bytes
/// (`is_duplicate_write` only drops redundant reads), and the search reports a match per leaf
/// interval. So it splits an occurrence that never stopped holding the needle, and the two sides
/// are compared on intervals rather than on that split. Two intervals that *overlap* are still a
/// defect, and still fail here.
fn occurrences(matches: Vec<SearchMatch>) -> Vec<SearchMatch> {
    let mut matches = matches;
    matches.sort_by_key(|found| (found.addr_min, found.addr_max, found.time_min));

    let mut merged: Vec<SearchMatch> = Vec::new();
    for found in matches {
        match merged.last_mut() {
            Some(last)
                if last.addr_min == found.addr_min
                    && last.addr_max == found.addr_max
                    && found.time_min <= last.time_max.saturating_add(1) =>
            {
                assert!(
                    found.time_min > last.time_max,
                    "{found:?} overlaps {last:?}"
                );
                last.time_max = last.time_max.max(found.time_max);
            }
            _ => merged.push(found),
        }
    }

    merged
}

// 4. The comparison

fuzz_target!(|input: Input| {
    let trace = build(&input);
    let db = trace.db();

    // shared by every needle, the trace does not change between them
    let snapshots: Vec<Vec<Vec<Option<u8>>>> =
        CLUSTERS.iter().map(|base| trace.snapshots(*base)).collect();

    for needle in &NEEDLES {
        let found = occurrences(search_pattern(&db, &needle.pattern(), &Task::new()));
        let expected = occurrences(trace.expected_matches(&snapshots, needle));

        assert_eq!(
            found,
            expected,
            "search of {} over {:#x?}, trace ending at {}",
            needle.label(),
            trace.writes,
            trace.time_end
        );
    }
});
