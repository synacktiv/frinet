use core::mem;

use crate::memory::{MemReadSpec, MemWriteSpec};
use crate::rtree::Spec;
use crate::scalar::ScalarSize;

use crate::irange::IRange;

use super::{
    ByTimeChunk, DB_MAGIC, Header, Level, RTreeHeader, RegisterByTimeHeader, RegisterByValueHeader,
    Section, StorageMut, Time,
};

/// Lay out plan of the database flat storage
#[derive(Debug, Clone, Default)]
pub struct DbPlan {
    pub metadata_json: String,

    /// Memory writes R-Trees
    pub write_zones: Vec<RTreePlan<MemWriteSpec>>,
    /// Memory reads R-Trees
    pub read_zones: Vec<RTreePlan<MemReadSpec>>,

    /// Index to obtain register value by time
    pub registers_by_time: Vec<RegisterByTimePlan>,
    /// Index to obtain register update times by value
    pub registers_by_value: Vec<RegisterByValuePlan>,

    /// Upper bound of the data section size, before deduplication
    pub data_bytes: usize,
}

/// Shape of a packed R-Tree
#[derive(Debug, Clone)]
pub struct RTreePlan<S: Spec> {
    pub node_size_order: u8,
    pub bbox: S::Node,
    pub leaf_count: usize,
    pub levels: Vec<Level>,
}

impl<S: Spec> RTreePlan<S> {
    pub fn new(bbox: S::Node, leaf_count: usize, node_size_order: u8) -> Self {
        Self {
            node_size_order,
            bbox,
            leaf_count,
            levels: build_rtree_levels(leaf_count, node_size_order),
        }
    }

    pub fn node_count(&self) -> usize {
        self.levels.iter().map(|level| level.size as usize).sum()
    }
}

/// Shape of a register by time index
#[derive(Debug, Clone)]
pub struct RegisterByTimePlan {
    pub scalar_size: ScalarSize,
    pub time_range: IRange<Time>,
    pub chunks: Vec<ByTimeChunk>,
    pub local_time_pool_len: usize,
    pub value_pool_len: usize,
}

/// Register by value index, its keys and offsets are written by [DbPlan::init_storage]
#[derive(Debug, Clone)]
pub struct RegisterByValuePlan {
    pub register_idx: usize,
    pub scalar_size: ScalarSize,
    /// Sorted distinct scalars, little-endian
    pub keys_le: Vec<u8>,
    /// Prefix sums of the write counts of each key, `len == keys + 1`
    pub offsets: Vec<u64>,
}

fn build_rtree_levels(leaf_count: usize, node_size_order: u8) -> Vec<Level> {
    let group_size = 1_usize.checked_shl(node_size_order.into()).unwrap();

    let mut levels = Vec::new();

    let mut node_count = 0;
    let mut prev_level_count = leaf_count;
    while prev_level_count > group_size {
        let level_count = prev_level_count.div_ceil(group_size);
        levels.push(Level {
            offset: node_count as u64,
            size: level_count as u64,
        });
        node_count += level_count;
        prev_level_count = level_count;
    }

    levels.reverse();
    levels
}

impl DbPlan {
    /// Size in bytes of the storage (with the data section not yet deduplicated)
    pub fn storage_size(&self) -> usize {
        lay_out(self, None)
    }

    /// Write the header, metadata, R-Tree headers and levels, register headers and by value
    /// keys and offsets
    ///
    /// Leaves, nodes, register times and values, and data are left to be filled by the caller.
    pub fn init_storage<'s>(&self, bytes: &'s mut [u8]) -> StorageMut<'s> {
        assert_eq!(bytes.len(), self.storage_size());
        let mut storage = StorageMut::new(bytes);
        lay_out(self, Some(&mut storage));
        storage
    }
}

#[derive(Default)]
struct Cursor {
    pos: usize,
}

impl Cursor {
    fn section<P>(&mut self, len: usize) -> Section<P> {
        self.pos = self.pos.next_multiple_of(mem::align_of::<P>());
        let offset = self.pos;
        self.pos += len * mem::size_of::<P>();
        Section::new(offset as u64, len as u64)
    }
}

/// Compute the layout, and write it if `out` is provided. Returns the storage size.
fn lay_out(plan: &DbPlan, sout: Option<&mut StorageMut<'_>>) -> usize {
    let mut cursor = Cursor::default();

    let header_section: Section<Header> = cursor.section(1);
    debug_assert_eq!(header_section.offset, 0);

    let mut header = Header {
        magic: DB_MAGIC,
        metadata: cursor.section(plan.metadata_json.len()),
        data: Section::default(),
        write_zones: cursor.section(plan.write_zones.len()),
        read_zones: cursor.section(plan.read_zones.len()),
        registers_by_time: cursor.section(plan.registers_by_time.len()),
        registers_by_value: cursor.section(plan.registers_by_value.len()),
    };

    // Pack R-Tree headers and levels to improve page caching
    let mut write_zones = rtree_headers(&plan.write_zones);
    let mut read_zones = rtree_headers(&plan.read_zones);

    lay_out_levels(&mut cursor, &mut write_zones, &plan.write_zones);
    lay_out_levels(&mut cursor, &mut read_zones, &plan.read_zones);

    lay_out_nodes_and_leaves(&mut cursor, &mut write_zones, &plan.write_zones);
    lay_out_nodes_and_leaves(&mut cursor, &mut read_zones, &plan.read_zones);

    let registers_by_time = lay_out_registers_by_time(&mut cursor, &plan.registers_by_time);
    let registers_by_value = lay_out_registers_by_value(&mut cursor, &plan.registers_by_value);

    // data section at the end, will be truncated after deduplication
    header.data = cursor.section(plan.data_bytes);

    if let Some(out) = sout {
        *out.header_mut() = header;

        // SAFETY: sections from the layout are disjoint, and not borrowed yet
        unsafe {
            out.slice_mut(header.metadata)
                .copy_from_slice(plan.metadata_json.as_bytes());
            write_rtrees(out, header.write_zones, &write_zones, &plan.write_zones);
            write_rtrees(out, header.read_zones, &read_zones, &plan.read_zones);
            write_registers(
                out,
                &header,
                &registers_by_time,
                &plan.registers_by_time,
                &registers_by_value,
                &plan.registers_by_value,
            );
        }
    }

    cursor.pos
}

fn rtree_headers<S: Spec>(plans: &[RTreePlan<S>]) -> Vec<RTreeHeader<S>> {
    plans
        .iter()
        .map(|plan| RTreeHeader {
            node_size_order: plan.node_size_order.into(),
            bbox: plan.bbox,
            leaves: Section::default(),
            nodes: Section::default(),
            levels: Section::default(),
        })
        .collect()
}

fn lay_out_levels<S: Spec>(
    cursor: &mut Cursor,
    headers: &mut [RTreeHeader<S>],
    plans: &[RTreePlan<S>],
) {
    for (header, plan) in headers.iter_mut().zip(plans) {
        header.levels = cursor.section(plan.levels.len());
    }
}

fn lay_out_nodes_and_leaves<S: Spec>(
    cursor: &mut Cursor,
    headers: &mut [RTreeHeader<S>],
    plans: &[RTreePlan<S>],
) {
    for (header, plan) in headers.iter_mut().zip(plans) {
        header.nodes = cursor.section(plan.node_count());
        header.leaves = cursor.section(plan.leaf_count);
    }
}

/// # Safety
///
/// `section` and levels sections must not be borrowed
unsafe fn write_rtrees<S: Spec>(
    out: &StorageMut<'_>,
    section: Section<RTreeHeader<S>>,
    headers: &[RTreeHeader<S>],
    plans: &[RTreePlan<S>],
) {
    unsafe {
        out.slice_mut(section).copy_from_slice(headers);
        for (header, plan) in headers.iter().zip(plans) {
            out.slice_mut(header.levels).copy_from_slice(&plan.levels);
        }
    }
}

fn lay_out_registers_by_time(
    cursor: &mut Cursor,
    plans: &[RegisterByTimePlan],
) -> Vec<RegisterByTimeHeader> {
    plans
        .iter()
        .map(|plan| RegisterByTimeHeader {
            scalar_size_pod: plan.scalar_size.into_pod(),
            _padding: Default::default(),
            time_range: plan.time_range,
            chunks: cursor.section(plan.chunks.len()),
            local_time_pool: cursor.section(plan.local_time_pool_len),
            value_pool: cursor.section(plan.value_pool_len * plan.scalar_size.bytes()),
        })
        .collect()
}

fn lay_out_registers_by_value(
    cursor: &mut Cursor,
    plans: &[RegisterByValuePlan],
) -> Vec<RegisterByValueHeader> {
    plans
        .iter()
        .map(|plan| {
            debug_assert!(plan.keys_le.len().is_multiple_of(plan.scalar_size.bytes()));
            debug_assert_eq!(
                plan.offsets.len(),
                plan.keys_le.len() / plan.scalar_size.bytes() + 1
            );
            let times_len = *plan.offsets.last().unwrap();

            RegisterByValueHeader {
                register_idx: plan.register_idx.try_into().unwrap(),
                scalar_size_pod: plan.scalar_size.into_pod(),
                _padding: Default::default(),
                keys: cursor.section(plan.keys_le.len()),
                offsets: cursor.section(plan.offsets.len()),
                times: cursor.section(times_len.try_into().unwrap()),
            }
        })
        .collect()
}

/// # Safety
///
/// Register header sections, by time chunks, and by value keys and offsets sections must not
/// be borrowed
unsafe fn write_registers(
    out: &StorageMut<'_>,
    header: &Header,
    by_time: &[RegisterByTimeHeader],
    by_time_plans: &[RegisterByTimePlan],
    by_value: &[RegisterByValueHeader],
    by_value_plans: &[RegisterByValuePlan],
) {
    unsafe {
        out.slice_mut(header.registers_by_time)
            .copy_from_slice(by_time);
        out.slice_mut(header.registers_by_value)
            .copy_from_slice(by_value);

        for (header, plan) in by_time.iter().zip(by_time_plans) {
            out.slice_mut(header.chunks).copy_from_slice(&plan.chunks);
        }

        for (header, plan) in by_value.iter().zip(by_value_plans) {
            out.slice_mut(header.keys).copy_from_slice(&plan.keys_le);
            out.slice_mut(header.offsets).copy_from_slice(&plan.offsets);
        }
    }
}
