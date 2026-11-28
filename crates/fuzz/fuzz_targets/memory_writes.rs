#![no_main]

use arbitrary::Arbitrary;
use frinet_db::{
    db::{Db, RegisterInfo},
    format::{Addr, MemNode, Time},
    irange::IRange,
    scalar::{Scalar, ScalarSize},
};
use frinet_index::{
    build_index,
    parser::{MemoryMode, RawEvent, StaticEventList, TimedRawEvent, TraceHeader},
    storage::VecStorage,
};
use libfuzzer_sys::fuzz_target;

/// Far apart, so the index builds one zone per cluster
const CLUSTERS: [Addr; 3] = [0x1000, 0x7fff_0000, 0xdead_0000_0000];

/// Narrow, so writes collide and the index fragments its rectangles, which uniformly drawn
/// `u64` addresses would never do
const CLUSTER_SPAN: Addr = 64;

const MAX_WRITES: usize = 32;
const MAX_QUERIES: usize = 32;
/// Over 8 bytes the content goes to the deduplicated data section instead of the leaf
const MAX_DATA: usize = 16;
const MAX_READ: Addr = 64;

// 1. Input

#[derive(Arbitrary, Debug)]
struct Input {
    writes: Vec<Write>,
    /// Steps after the last write, so the trace outlives the content it holds
    tail: u8,
    queries: Vec<Query>,
}

#[derive(Arbitrary, Debug)]
struct Write {
    time: u8,
    cluster: u8,
    offset: u8,
    /// Empty data is rejected by the indexer, [build] drops such a write
    data: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Query {
    time: u8,
    cluster: u8,
    offset: u8,
    len: u8,
}

fn addr_of(cluster: u8, offset: u8) -> Addr {
    CLUSTERS[usize::from(cluster) % CLUSTERS.len()] + Addr::from(offset) % CLUSTER_SPAN
}

// 2. The trace built from the input

#[derive(Debug, Clone)]
struct MemWrite {
    time: Time,
    addr: Addr,
    data: Vec<u8>,
}

impl MemWrite {
    fn addrs(&self) -> IRange<Addr> {
        IRange::from_start_len(self.addr, self.data.len() as Addr)
    }
}

struct Trace {
    /// In time order, the ones sharing a time in the order the index applies them
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
            data: write.data[..write.data.len().min(MAX_DATA)].to_vec(),
        })
        .collect();

    // the indexer asserts non decreasing times; a stable sort keeps the writes sharing a time
    // in input order, which is the order it applies them in
    writes.sort_by_key(|write| write.time);

    let last_write = writes.last().map_or(0, |write| write.time);
    let time_end = last_write + Time::from(input.tail);

    // the trace ends on its last event, so a register write past the last memory write is what
    // makes the content outlive it
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

    /// Content of `addrs` at `time`, [None] for a byte no write has revealed yet
    fn bytes_at(&self, addrs: IRange<Addr>, time: Time) -> Vec<Option<u8>> {
        // a read is capped to the end of the trace, where nothing changes anymore
        let time = time.min(self.time_end);
        let len = addrs.span_usize();
        let mut out = vec![None; len];

        for write in self.writes.iter().filter(|write| write.time <= time) {
            for (offset, byte) in write.data.iter().enumerate() {
                let written = write.addr + offset as Addr;
                if let Some(idx) = written
                    .checked_sub(addrs.min)
                    .filter(|idx| *idx < len as Addr)
                {
                    out[idx as usize] = Some(*byte);
                }
            }
        }

        out
    }

    fn overlapping(&self, addrs: IRange<Addr>) -> impl Iterator<Item = &MemWrite> {
        self.writes
            .iter()
            .filter(move |write| !write.addrs().is_disjoint(addrs))
    }

    fn next_write(&self, time: Time, addrs: IRange<Addr>) -> Option<Time> {
        self.overlapping(addrs)
            .map(|write| write.time)
            .filter(|write| *write > time)
            .min()
    }

    fn prev_write(&self, time: Time, addrs: IRange<Addr>) -> Option<Time> {
        self.overlapping(addrs)
            .map(|write| write.time)
            .filter(|write| *write < time)
            .max()
    }
}

/// The exact range of every write around its own time, where a leaf starts and ends, plus the
/// ones the input asks for
fn queries(trace: &Trace, input: &Input) -> Vec<(IRange<Addr>, Time)> {
    let mut queries = Vec::new();

    for write in &trace.writes {
        for time in [
            write.time.saturating_sub(1),
            write.time,
            write.time + 1,
            trace.time_end,
            trace.time_end + 1,
        ] {
            queries.push((write.addrs(), time));
        }
    }

    for query in input.queries.iter().take(MAX_QUERIES) {
        let addr = addr_of(query.cluster, query.offset);
        let len = 1 + Addr::from(query.len) % MAX_READ;
        queries.push((IRange::from_start_len(addr, len), Time::from(query.time)));
    }

    queries
}

// 4. The comparison

fuzz_target!(|input: Input| {
    let trace = build(&input);
    let db = trace.db();

    // nothing is ever read, so the read index holds no leaf at all
    assert!(
        db.mem_read_intersects(MemNode {
            addr: IRange::new(0, Addr::MAX),
            time: IRange::new(0, Time::MAX),
        })
        .next()
        .is_none(),
        "a write only trace has no read leaf"
    );

    for (addrs, time) in queries(&trace, &input) {
        let expected = trace.bytes_at(addrs, time);

        assert_eq!(
            db.read_memory_with_unknowns(addrs, time),
            expected,
            "read_memory_with_unknowns({addrs:x?}, {time})"
        );
        assert_eq!(
            db.read_memory(addrs, time),
            expected
                .iter()
                .map(|byte| byte.unwrap_or_default())
                .collect::<Vec<_>>(),
            "read_memory({addrs:x?}, {time})"
        );

        assert_eq!(
            db.next_mem_write(time, addrs),
            trace.next_write(time, addrs),
            "next_mem_write({addrs:x?}, {time})"
        );
        assert_eq!(
            db.prev_mem_write(time, addrs),
            trace.prev_write(time, addrs),
            "prev_mem_write({addrs:x?}, {time})"
        );

        assert_eq!(
            db.next_mem_read(time, addrs),
            None,
            "next_mem_read({addrs:x?}, {time})"
        );
        assert_eq!(
            db.prev_mem_read(time, addrs),
            None,
            "prev_mem_read({addrs:x?}, {time})"
        );

        // with no read, an access is a content update
        assert_eq!(
            db.next_mem_access(time, addrs),
            trace.next_write(time, addrs),
            "next_mem_access({addrs:x?}, {time})"
        );
        assert_eq!(
            db.prev_mem_access(time, addrs),
            trace.prev_write(time, addrs),
            "prev_mem_access({addrs:x?}, {time})"
        );
    }
});
