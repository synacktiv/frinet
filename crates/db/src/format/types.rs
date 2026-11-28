use core::fmt;
use core::marker::PhantomData;
use core::mem;
use core::ops::Range;

use crate::irange::IRange;
use crate::memory::{MemReadSpec, MemWriteSpec};
use crate::rtree::Spec;
use crate::scalar::{ScalarSize, ScalarSizePod};
use crate::time_series::LocalTime;

/// Plain old data, can be viewed from any properly aligned bytes
///
/// # Safety
///
/// Implementors must have a stable layout (`repr(C)` or primitive), no padding bytes,
/// and every bit pattern must be a valid value.
pub unsafe trait Pod: Copy + Send + Sync + 'static {}

// SAFETY: primitive
unsafe impl Pod for u8 {}
// SAFETY: primitive
unsafe impl Pod for u16 {}
// SAFETY: primitive
unsafe impl Pod for u32 {}
// SAFETY: primitive
unsafe impl Pod for u64 {}

/// View a value as raw bytes
pub fn bytes_of<T: Pod>(value: &T) -> &[u8] {
    // SAFETY: `T` is Pod, it has no padding bytes
    unsafe { core::slice::from_raw_parts((value as *const T).cast(), mem::size_of::<T>()) }
}

pub fn slice_of<T: Pod>(values: &[T]) -> &[u8] {
    let len = mem::size_of_val(values);
    // SAFETY: `T` is Pod, it has no padding bytes
    unsafe { core::slice::from_raw_parts(values.as_ptr().cast(), len) }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Header {
    pub magic: [u8; 8],
    pub metadata: Section<u8>,
    pub data: Section<u8>,
    pub write_zones: Section<RTreeHeader<MemWriteSpec>>,
    pub read_zones: Section<RTreeHeader<MemReadSpec>>,
    pub registers_by_time: Section<RegisterByTimeHeader>,
    pub registers_by_value: Section<RegisterByValueHeader>,
}

// SAFETY: repr(C), no padding
unsafe impl Pod for Header {}

/// Packed R-Tree
#[repr(C)]
pub struct RTreeHeader<S: Spec> {
    /// node_size = 1 << node_size_order
    pub node_size_order: u64,
    /// Bounding box of all leaves
    pub bbox: S::Node,
    pub leaves: Section<S::Leaf>,
    pub nodes: Section<S::Node>,
    /// Node levels, from the root to the leaves
    pub levels: Section<Level>,
}

// SAFETY: repr(C), no padding as long as `S::Node` size is a multiple of 8
unsafe impl<S: Spec> Pod for RTreeHeader<S> {}

impl<S: Spec> Clone for RTreeHeader<S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S: Spec> Copy for RTreeHeader<S> {}

/// Node level of a R-Tree
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct Level {
    /// Offset in rtree.nodes
    pub offset: u64,
    /// Number of nodes
    pub size: u64,
}

// SAFETY: repr(C), no padding
unsafe impl Pod for Level {}

/// Typed range of items inside the storage, aligned on `align_of::<P>()`
#[repr(C)]
pub struct Section<P> {
    /// bytes offset from the storage start
    pub offset: u64,
    pub item_len: u64,
    _item: PhantomData<P>,
}

// SAFETY: repr(C), no padding
unsafe impl<P: Pod> Pod for Section<P> {}

impl<P> Section<P> {
    pub const fn new(offset: u64, item_len: u64) -> Self {
        Self {
            offset,
            item_len,
            _item: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.item_len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.item_len == 0
    }

    /// Range in bytes inside the storage, panics on overflow
    pub fn byte_range(&self) -> Range<usize> {
        let start = usize::try_from(self.offset).unwrap();
        let item_len = usize::try_from(self.item_len).unwrap();
        let len = item_len.checked_mul(mem::size_of::<P>()).unwrap();
        let end = start.checked_add(len).unwrap();
        start..end
    }

    pub fn sub_section(&self, item_range: Range<usize>) -> Self {
        assert!(item_range.start <= item_range.end && item_range.end <= self.len());
        let offset = self.offset + (item_range.start * mem::size_of::<P>()) as u64;
        Self::new(offset, item_range.len() as u64)
    }
}

impl<P> Clone for Section<P> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<P> Copy for Section<P> {}

impl<P> Default for Section<P> {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl<P> fmt::Debug for Section<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Section")
            .field("offset", &self.offset)
            .field("item_len", &self.item_len)
            .finish()
    }
}

pub type Addr = u64;
pub type Time = u32;

// SAFETY: repr(C) over two `u64`, no padding
unsafe impl Pod for IRange<Addr> {}

// SAFETY: repr(C) over two `u32`, no padding
unsafe impl Pod for IRange<Time> {}

/// Written data of a mem write leaf : either <= 8 bytes inlined or an offset
pub type U64OrOffset = u64;

/// R-Tree non-leaf node for memory (reads/writes) indexing
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct MemNode {
    pub addr: IRange<Addr>,
    pub time: IRange<Time>,
}

// SAFETY: repr(C), no padding
unsafe impl Pod for MemNode {}

/// R-Tree leaf node for memory writes indexing
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct MemWriteLeaf {
    pub node: MemNode,
    pub data: U64OrOffset,
}

// SAFETY: repr(C), no padding
unsafe impl Pod for MemWriteLeaf {}

/// R-Tree leaf node for memory reads indexing
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct MemReadLeaf {
    pub addr: IRange<Addr>,
    pub time: Time,
}

// SAFETY: repr(C, packed), no padding
unsafe impl Pod for MemReadLeaf {}

/// Encoding of one chunk of a register by time index
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ChunkKind {
    Sparse = 0,
    Dense = 1,
}

/// [ChunkKind] as stored in the DB, may be invalid
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct ChunkKindPod(pub u8);

// SAFETY: repr(transparent) over `u8`
unsafe impl Pod for ChunkKindPod {}

impl ChunkKind {
    pub fn into_pod(self) -> ChunkKindPod {
        ChunkKindPod(self as u8)
    }

    pub fn try_from_pod(pod: ChunkKindPod) -> Option<Self> {
        match pod.0 {
            0 => Some(Self::Sparse),
            1 => Some(Self::Dense),
            _ => None,
        }
    }
}

/// Directory entry of a by time chunk
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct ByTimeChunk {
    pub value_pool_offset: u32,
    pub local_time_pool_offset: u32,
    pub kind_pod: ChunkKindPod,
    pub _padding: u8,
    pub local_time_len: u16,
}

impl ByTimeChunk {
    pub fn kind(&self) -> ChunkKind {
        ChunkKind::try_from_pod(self.kind_pod).unwrap()
    }
}

// SAFETY: repr(C), no padding
unsafe impl Pod for ByTimeChunk {}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RegisterByTimeHeader {
    pub scalar_size_pod: ScalarSizePod,
    pub _padding: [u8; 7],

    pub time_range: IRange<Time>,
    pub chunks: Section<ByTimeChunk>,

    pub local_time_pool: Section<LocalTime>,
    pub value_pool: Section<u8>,
}

impl RegisterByTimeHeader {
    pub fn scalar_size(&self) -> ScalarSize {
        ScalarSize::try_from_pod(self.scalar_size_pod).unwrap()
    }
}

// SAFETY: repr(C), no padding
unsafe impl Pod for RegisterByTimeHeader {}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RegisterByValueHeader {
    pub register_idx: u32,

    pub scalar_size_pod: ScalarSizePod,
    pub _padding: [u8; 3],

    pub keys: Section<u8>,
    pub offsets: Section<u64>,
    pub times: Section<Time>,
}

impl RegisterByValueHeader {
    pub fn scalar_size(&self) -> ScalarSize {
        ScalarSize::try_from_pod(self.scalar_size_pod).unwrap()
    }
}

// SAFETY: repr(C), no padding
unsafe impl Pod for RegisterByValueHeader {}
