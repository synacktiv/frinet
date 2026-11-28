use core::mem;
use frinet_db::format::{
    ByTimeChunk, ChunkKind, Header, MemWriteLeaf, RTreeHeader, RegisterByTimeHeader,
    RegisterByValueHeader, Section, StorageMut, Time, U64OrOffset,
};
use frinet_db::irange::IRange;
use frinet_db::scalar::{Scalar, ScalarSize};
use frinet_db::time_series::{LocalTime, chunk_index_at, time_range_covered_by_a_chunk};
use hashbrown::{HashMap, hash_map::RawEntryMut};
use log::trace;

use crate::{
    hilbert_spec::HilbertSpec,
    parser::{Parser, ProgressReporter},
    pass::{
        Event, HilbertPartitionPass, PARTITIONS, RegisterValue, find_zone_containing_addr_range,
        parse_and_normalize_events,
    },
};

use super::RTreePartitions;

pub struct FillPass {
    pub data_used: usize,
}

/// Fill leaves, register series and data sections of an initialized storage
pub fn fill_pass<'s, P>(
    mut parser: P,
    progress: &mut dyn ProgressReporter,
    storage: &StorageMut<'s>,
    partitions: &HilbertPartitionPass,
) -> Result<Option<FillPass>, P::Err>
where
    P: Parser,
{
    let header = *storage.header();

    // SAFETY: R-Tree headers are only read during this pass,
    // the data section is only borrowed here
    let (write_zones, read_zones, data) = unsafe {
        (
            storage.slice(header.write_zones),
            storage.slice(header.read_zones),
            storage.slice_mut(header.data),
        )
    };

    // SAFETY: register sections are only borrowed here
    let mut registers = unsafe { register_fills(storage, &header) };

    let data_start_ptr = data.as_ptr();
    let mut dedup = DataDedup::new(data);

    let mut mem_leaf_buffers = leaf_buffers(write_zones);
    let mut mem_read_leaf_buffers = leaf_buffers(read_zones);

    rayon::in_place_scope(|scope| {
        parse_and_normalize_events(&mut parser, progress, |item| match item {
            Event::MemoryWrite(leaf) => {
                let addr_range = leaf.node.addr;
                let idx = find_zone_containing_addr_range(&partitions.write_zones, addr_range);

                let bytes = leaf.bytes;
                let packed_data = if bytes.len() <= size_of::<U64OrOffset>() {
                    // Not portable, but will be checked in the index header
                    let mut inline = [0; size_of::<U64OrOffset>()];
                    inline[..bytes.len()].copy_from_slice(bytes);
                    U64OrOffset::from_ne_bytes(inline)
                } else {
                    let data = dedup.insert(bytes);
                    (data.as_ptr().addr() - data_start_ptr.addr()) as U64OrOffset
                };

                let leaf = MemWriteLeaf {
                    node: leaf.node,
                    data: packed_data,
                };

                push_leaf_into_partition(
                    scope,
                    storage,
                    write_zones[idx].leaves,
                    &mut mem_leaf_buffers[idx],
                    &partitions.write_zones[idx],
                    leaf,
                );
            }
            Event::MemoryRead(leaf) => {
                let idx = find_zone_containing_addr_range(&partitions.read_zones, leaf.addr);

                push_leaf_into_partition(
                    scope,
                    storage,
                    read_zones[idx].leaves,
                    &mut mem_read_leaf_buffers[idx],
                    &partitions.read_zones[idx],
                    leaf,
                );
            }
            Event::Register { idx, time, value } => {
                registers[idx].push(time, value);
            }
        })
    })?;

    if progress.is_cancelled() {
        return Ok(None);
    }

    for register in registers {
        register.finish();
    }

    // all temporary leaf buffers must be empty after indexing
    assert_buffers_are_empty(&mem_leaf_buffers);
    assert_buffers_are_empty(&mem_read_leaf_buffers);

    let data_used = dedup.bytes_used();

    Ok(Some(FillPass { data_used }))
}

type LeafBuffers<Leaf> = Box<[Vec<Leaf>; PARTITIONS]>;

fn leaf_buffers<S: HilbertSpec>(trees: &[RTreeHeader<S>]) -> Vec<LeafBuffers<S::Leaf>> {
    trees
        .iter()
        .map(|_| Box::new([const { Vec::new() }; PARTITIONS]))
        .collect()
}

fn assert_buffers_are_empty<Leaf>(buffers: &[LeafBuffers<Leaf>]) {
    for buffers in buffers {
        for buffer in buffers.iter() {
            assert!(buffer.is_empty());
        }
    }
}

fn push_leaf_into_partition<'scope, S>(
    scope: &rayon::Scope<'scope>,
    storage: &StorageMut<'scope>,
    leaves: Section<S::Leaf>,
    leaves_buffer: &mut LeafBuffers<S::Leaf>,
    partitions: &RTreePartitions<S>,
    leaf: S::Leaf,
) where
    S: HilbertSpec,
{
    let bbox = partitions.bbox;

    let part_idx = S::hilbert_partition_key(&leaf, &bbox);
    let part_idx = usize::from(part_idx);

    let leaf_buffer = &mut leaves_buffer[part_idx];
    let leaf_partition = &partitions.partitions[part_idx];

    leaf_buffer.push(leaf);

    if leaf_buffer.len() == leaf_partition.leaf_count {
        let mut unsorted_leaves = mem::take(leaf_buffer);

        // SAFETY: partitions are disjoint ranges of the leaves section,
        // and each one is borrowed exactly once, when it is complete
        let out_sorted_leaves = unsafe {
            let section = leaves.sub_section(leaf_partition.range());
            storage.slice_mut(section)
        };

        scope.spawn(move |_| {
            trace!("Task partition : partition:{part_idx}");
            unsorted_leaves.sort_by_cached_key(|leaf| S::hilbert_key(leaf, &bbox));
            out_sorted_leaves.copy_from_slice(&unsorted_leaves);
        });
    }
}

/// Raw data deduplication directly inside the memory mapping
struct DataDedup<'storage> {
    used: usize,
    storage_rest: &'storage mut [u8],
    memo: hashbrown::HashMap<&'storage [u8], ()>,
}

impl<'s> DataDedup<'s> {
    fn new(storage: &'s mut [u8]) -> Self {
        Self {
            used: 0,
            memo: Default::default(),
            storage_rest: storage,
        }
    }

    fn bytes_used(&self) -> usize {
        self.used
    }

    /// Insert and deduplicate a byte-slice from anywhere inside the memory mapping
    fn insert(&mut self, data: &'_ [u8]) -> &'s [u8] {
        // raw entry manipulation :
        // - the memo is queried with byte slices from unknown lifetime
        // - the memo is populated with byte slices in the memory mapping

        match self.memo.raw_entry_mut().from_key(data) {
            RawEntryMut::Occupied(some) => some.get_key_value().0,
            RawEntryMut::Vacant(none) => {
                // temporarily steal `self.storage_rest`
                let storage_rest = mem::replace(&mut self.storage_rest, &mut [][..]);

                let (slot, new_rest) = storage_rest.split_at_mut(data.len());
                slot.copy_from_slice(data);
                self.used += data.len();

                // restore `self.storage_rest`
                self.storage_rest = new_rest;

                none.insert(slot, ());

                // return the slice inside the memory mapping
                &*slot
            }
        }
    }
}

/// # Safety
///
/// Register sections must not be borrowed
unsafe fn register_fills<'s>(storage: &StorageMut<'s>, header: &Header) -> Vec<RegisterFill<'s>> {
    unsafe {
        let mut registers: Vec<_> = storage
            .slice(header.registers_by_time)
            .iter()
            .map(|by_time| RegisterFill::new(storage, by_time))
            .collect();

        for by_value in storage.slice(header.registers_by_value) {
            let register = &mut registers[by_value.register_idx as usize];
            assert!(register.by_value.is_none());
            register.by_value = Some(ByValueFill::new(storage, by_value));
        }

        registers
    }
}

/// Writer of the series of a register, in write order
///
/// Values are copied as little-endian bytes, the storage representation of the scalars.
struct RegisterFill<'s> {
    size: ScalarSize,
    by_time: ByTimeFill<'s>,
    by_value: Option<ByValueFill<'s>>,
}

/// Every sample of every chunk is written exactly once, in write order
struct ByTimeFill<'s> {
    time: IRange<Time>,
    chunks: &'s [ByTimeChunk],
    local_time_pool: &'s mut [LocalTime],
    value_pool: &'s mut [u8],
    /// Number of filled samples
    value_len: usize,
    /// Number of filled write times
    time_len: usize,
}

/// `times[cursors[value]]` is the slot of the next write of `value`
struct ByValueFill<'s> {
    byte_size: usize,
    keys: &'s [u8],
    offsets: &'s [u64],
    times: &'s mut [Time],
    cursors: HashMap<&'s [u8], u64>,
}

impl<'s> RegisterFill<'s> {
    /// # Safety
    ///
    /// Sections of `header` must not be borrowed
    unsafe fn new(storage: &StorageMut<'s>, header: &RegisterByTimeHeader) -> Self {
        Self {
            size: header.scalar_size(),
            // SAFETY: up to the caller
            by_time: unsafe {
                ByTimeFill {
                    time: header.time_range,
                    chunks: storage.slice(header.chunks),
                    local_time_pool: storage.slice_mut(header.local_time_pool),
                    value_pool: storage.slice_mut(header.value_pool),
                    value_len: 0,
                    time_len: 0,
                }
            },
            by_value: None,
        }
    }

    fn push(&mut self, time: Time, value: RegisterValue<'_>) {
        self.by_time.push(self.size.bytes(), time, value);

        if let Some(by_value) = &mut self.by_value {
            match value {
                RegisterValue::Scalar(value) => {
                    by_value.push(time, value);
                }
                RegisterValue::Module(_) => todo!("module register is not by-value indexable"),
            }
        }
    }

    fn finish(mut self) {
        self.by_time.finish(self.size.bytes());

        if let Some(by_value) = &self.by_value {
            by_value.finish();
        }
    }
}

impl ByTimeFill<'_> {
    fn push(&mut self, byte_size: usize, time: Time, value: RegisterValue<'_>) {
        let idx = chunk_index_at(self.time, time);
        let chunk = self.chunks[idx];
        let covered = time_range_covered_by_a_chunk(self.time, idx);

        let value_slot = match chunk.kind() {
            ChunkKind::Sparse => {
                self.local_time_pool[self.time_len] = (time - covered.min) as u16;
                self.time_len += 1;
                self.value_len
            }
            ChunkKind::Dense => chunk.value_pool_offset as usize + (time - covered.min) as usize,
        };
        debug_assert_eq!(value_slot, self.value_len);

        value.copy_to(&mut self.value_pool[value_slot * byte_size..][..byte_size]);
        self.value_len = value_slot + 1;
    }

    fn finish(&mut self, byte_size: usize) {
        assert_eq!(self.value_len, self.value_pool.len() / byte_size);
        assert_eq!(self.time_len, self.local_time_pool.len());
    }
}

impl<'s> ByValueFill<'s> {
    /// # Safety
    ///
    /// Sections of `register_header` must not be borrowed mutably
    unsafe fn new(storage: &StorageMut<'s>, register_header: &RegisterByValueHeader) -> Self {
        let byte_size = register_header.scalar_size().bytes();

        // SAFETY: up to the caller
        let (keys, offsets, times) = unsafe {
            (
                storage.slice(register_header.keys),
                storage.slice(register_header.offsets),
                storage.slice_mut(register_header.times),
            )
        };

        let cursors = keys
            .chunks_exact(byte_size)
            .zip(offsets)
            .map(|(key, offset)| (key, *offset))
            .collect();

        Self {
            byte_size,
            keys,
            offsets,
            times,
            cursors,
        }
    }

    fn push(&mut self, time: Time, value: Scalar<'_>) {
        let cursor = self.cursors.get_mut(value.0).unwrap();
        self.times[*cursor as usize] = time;
        *cursor += 1;
    }

    fn finish(&self) {
        // every write time slot is filled
        debug_assert!(
            self.keys
                .chunks_exact(self.byte_size)
                .zip(&self.offsets[1..])
                .all(|(key, end)| self.cursors[key] == *end)
        );
    }
}
