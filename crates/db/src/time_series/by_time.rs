use crate::format::{ByTimeChunk, ChunkKind, Time};
use crate::irange::IRange;
use crate::scalar::{Scalar, ScalarSlice};

/// Time span of a chunk
pub const CHUNK_STEPS: Time = 1 << CHUNK_LOG2;
pub const CHUNK_LOG2: u32 = 12;

/// Time relative to the start of a chunk
pub type LocalTime = u16;

const _: () = assert!(
    CHUNK_STEPS - 1 <= LocalTime::MAX as Time,
    "Chunk span fit in a LocalTime"
);

pub fn chunk_index_at(total_range: IRange<Time>, time: Time) -> usize {
    debug_assert!(total_range.contains(time));
    ((time >> CHUNK_LOG2) - (total_range.min >> CHUNK_LOG2)) as usize
}

pub fn number_of_chunk_covering_a_time_range(range: IRange<Time>) -> usize {
    chunk_index_at(range, range.max) + 1
}

pub fn time_range_covered_by_a_chunk(total_range: IRange<Time>, chunk_idx: usize) -> IRange<Time> {
    let min = ((total_range.min >> CHUNK_LOG2) + chunk_idx as Time) << CHUNK_LOG2;
    IRange::new(
        min.max(total_range.min),
        (min + CHUNK_STEPS - 1).min(total_range.max),
    )
}

/// Indexes values of a register using a chunked time series
#[derive(Debug, Clone, Copy)]
pub struct SeriesByTime<'s> {
    /// The total time range where this register has a known value
    total_time_range: IRange<Time>,
    /// Chunks of this time series
    chunks: &'s [ByTimeChunk],

    local_time_pool: &'s [LocalTime],
    value_pool: ScalarSlice<'s>,
}

impl<'s> SeriesByTime<'s> {
    /// A written register has at least one chunk
    pub fn new(
        total_time_range: IRange<Time>,
        chunks: &'s [ByTimeChunk],
        local_time_pool: &'s [LocalTime],
        value_pool: ScalarSlice<'s>,
    ) -> Self {
        assert!(!chunks.is_empty());
        assert_eq!(
            chunks.len(),
            number_of_chunk_covering_a_time_range(total_time_range)
        );

        Self {
            total_time_range,
            chunks,
            local_time_pool,
            value_pool,
        }
    }

    /// First write ..= end of the trace
    pub fn time_range(&self) -> IRange<Time> {
        self.total_time_range
    }

    /// Register value at a given time
    pub fn value_at(&self, time: Time) -> Option<Scalar<'s>> {
        let chunk = self.chunk_by_time(time)?;
        Some(match chunk.local_value_idx_at(time) {
            Some(local) => chunk.values.get(local),
            None => self.value_pool.get(self.value_pool_offset(chunk) - 1),
        })
    }

    /// Whether the instruction at `time` wrote the register, O(1) on both kinds of chunk
    pub fn is_write_at(&self, time: Time) -> bool {
        let Some(chunk) = self.chunk_by_time(time) else {
            return false;
        };
        match chunk.kind {
            ChunkKind::Dense => true,
            ChunkKind::Sparse => chunk
                .local_value_idx_at(time)
                .is_some_and(|local| chunk.sparse_time_of(local) == time),
        }
    }

    /// Last time before the write holding at `time`
    pub fn prev_change(&self, time: Time) -> Option<Time> {
        self.written_at(time)?.checked_sub(1)
    }

    /// First write after `time`
    pub fn next_change(&self, time: Time) -> Option<Time> {
        let total_time_range = self.total_time_range;
        if time > total_time_range.max {
            // nothing is known anymore
            return None;
        }
        if time < total_time_range.min {
            // before the first write, the next value is the first one
            return Some(total_time_range.min);
        }

        let mut after = Some(time);

        let chunk_start = chunk_index_at(total_time_range, time);
        let chunk_end = number_of_chunk_covering_a_time_range(total_time_range);

        for idx in chunk_start..chunk_end {
            if let Some(found) = self.chunk_by_idx(idx).next_write(after) {
                return Some(found);
            }
            // the following chunks are searched from their first sample
            after = None;
        }
        None
    }

    /// Write time of the sample holding at `time`, [None] when none holds
    fn written_at(&self, time: Time) -> Option<Time> {
        let (chunk, local) = self.holding_at(time)?;
        Some(chunk.write_time_of(local))
    }

    /// Where the value holding at `time` is: a chunk and an index inside it
    fn holding_at(&self, time: Time) -> Option<(ChunkRef<'s>, usize)> {
        let chunk = self.chunk_by_time(time)?;
        Some(match chunk.local_value_idx_at(time) {
            Some(local) => (chunk, local),
            // the previous sample still holds
            None => self.holding_before(chunk),
        })
    }

    /// The last sample before `chunk`, the first chunk always has one
    fn holding_before(&self, chunk: ChunkRef<'s>) -> (ChunkRef<'s>, usize) {
        // the empty chunks between the holding one and `chunk` start where `chunk` starts
        let start = self.chunks[chunk.idx].value_pool_offset;
        let holding_idx =
            self.chunks[..chunk.idx].partition_point(|entry| entry.value_pool_offset < start) - 1;
        let holding = self.chunk_by_idx(holding_idx);
        (holding, holding.values.len() - 1)
    }

    /// Index in the value pool of the first sample of `chunk`
    fn value_pool_offset(&self, chunk: ChunkRef<'s>) -> usize {
        self.chunks[chunk.idx].value_pool_offset as usize
    }

    /// `idx`-th chunk, its write times and its values
    fn chunk_by_idx(&self, idx: usize) -> ChunkRef<'s> {
        let entry = self.chunks[idx];
        let kind = entry.kind();
        let time_range = time_range_covered_by_a_chunk(self.total_time_range, idx);

        let local_times = &self.local_time_pool[entry.local_time_pool_offset as usize..]
            [..usize::from(entry.local_time_len)];
        let sample_len = match kind {
            ChunkKind::Sparse => local_times.len(),
            ChunkKind::Dense => time_range.span_usize(),
        };

        ChunkRef {
            idx,
            kind,
            time_range,
            local_times,
            values: self
                .value_pool
                .slice(entry.value_pool_offset as usize, sample_len),
        }
    }

    fn chunk_by_time(&self, time: Time) -> Option<ChunkRef<'s>> {
        let range = self.total_time_range;
        range
            .contains(time)
            .then(|| self.chunk_by_idx(chunk_index_at(range, time)))
    }
}

/// One chunk of a [SeriesByTime], the write times and the values it owns
#[derive(Debug, Clone, Copy)]
struct ChunkRef<'s> {
    idx: usize,
    kind: ChunkKind,
    time_range: IRange<Time>,
    local_times: &'s [LocalTime],
    values: ScalarSlice<'s>,
}

impl ChunkRef<'_> {
    fn local_value_idx_at(&self, time: Time) -> Option<usize> {
        match self.kind {
            ChunkKind::Sparse => {
                let local_time = self.to_local_time(time);
                let next = self.local_times.partition_point(|it| *it <= local_time);
                next.checked_sub(1)
            }
            ChunkKind::Dense => Some(self.dense_step_of(time)),
        }
    }

    /// Write time of sample `local` in this chunk
    fn write_time_of(&self, local: usize) -> Time {
        match self.kind {
            ChunkKind::Dense => self.time_range.min + local as Time,
            ChunkKind::Sparse => self.sparse_time_of(local),
        }
    }

    /// First write strictly after `after`, or the first one of the chunk if [None]
    fn next_write(&self, after: Option<Time>) -> Option<Time> {
        let from = match after {
            None => 0,
            Some(time) => match self.kind {
                ChunkKind::Sparse => self
                    .local_times
                    .partition_point(|local| *local <= self.to_local_time(time)),
                ChunkKind::Dense => self.dense_step_of(time) + 1,
            },
        };
        (from < self.values.len()).then(|| self.write_time_of(from))
    }

    /// Index of the sample of the step `time` in a dense chunk
    fn dense_step_of(&self, time: Time) -> usize {
        debug_assert_eq!(self.kind, ChunkKind::Dense);
        usize::from(self.to_local_time(time))
    }

    /// Write time of the sample `local` of a sparse chunk
    fn sparse_time_of(&self, local: usize) -> Time {
        debug_assert_eq!(self.kind, ChunkKind::Sparse);
        self.time_range.min + Time::from(self.local_times[local])
    }

    fn to_local_time(&self, time: Time) -> LocalTime {
        debug_assert!(self.time_range.contains(time));
        (time - self.time_range.min) as LocalTime
    }
}
