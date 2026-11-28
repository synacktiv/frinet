use core::cmp::Ordering;
use core::fmt::{self, Debug};

use serde::{Deserialize, Serialize};

use crate::format::Pod;

/// Enumeration of supported scalar sizes
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[derive(Serialize, Deserialize)]
#[repr(u8)]
pub enum ScalarSize {
    U8 = 0,
    U16 = 1,
    U32 = 2,
    U64 = 3,
    U128 = 4,
    U256 = 5,
    U512 = 6,
}

/// [ScalarSize] as stored in the DB, may be invalid
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct ScalarSizePod(pub u8);

// SAFETY: repr(transparent) over `u8`
unsafe impl Pod for ScalarSizePod {}

impl ScalarSize {
    pub const MAX_BYTE_SIZE: usize = ScalarSize::U512.bytes();

    pub const fn into_pod(self) -> ScalarSizePod {
        ScalarSizePod(self as u8)
    }

    pub const fn try_from_pod(pod: ScalarSizePod) -> Option<Self> {
        Self::try_from_log2(pod.0)
    }

    const fn try_from_log2(log2: u8) -> Option<Self> {
        Some(match log2 {
            0 => Self::U8,
            1 => Self::U16,
            2 => Self::U32,
            3 => Self::U64,
            4 => Self::U128,
            5 => Self::U256,
            6 => Self::U512,
            _ => return None,
        })
    }

    /// Size in bytes
    pub const fn bytes(self) -> usize {
        1 << self as u8
    }
}

/// Untyped scalar as its little-endian bytes, the storage representation
///
/// Ordered numerically: only scalars of the same size are comparable.
#[derive(Clone, Copy, Hash)]
pub struct Scalar<'a>(pub &'a [u8]);

impl Scalar<'_> {
    /// [None] if wider than 8 bytes
    pub fn try_into_u64(self) -> Option<u64> {
        // fixed size loads, sizes are powers of two
        Some(match *self.0 {
            [a] => a.into(),
            [a, b] => u16::from_le_bytes([a, b]).into(),
            [a, b, c, d] => u32::from_le_bytes([a, b, c, d]).into(),
            [a, b, c, d, e, f, g, h] => u64::from_le_bytes([a, b, c, d, e, f, g, h]),
            _ => return None,
        })
    }

    /// 64 bits words, from the least significant one, `len` must be a multiple of 8
    fn words(self) -> impl DoubleEndedIterator<Item = u64> {
        let (words, rest) = self.0.as_chunks::<8>();
        debug_assert!(rest.is_empty());
        words.iter().map(|word| u64::from_le_bytes(*word))
    }
}

impl PartialEq for Scalar<'_> {
    fn eq(&self, other: &Self) -> bool {
        if self.0.len() != other.0.len() {
            return false;
        }
        match (self.try_into_u64(), other.try_into_u64()) {
            (Some(a), Some(b)) => a == b,
            _ => self.0 == other.0,
        }
    }
}

impl Eq for Scalar<'_> {}

impl Ord for Scalar<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        debug_assert_eq!(self.0.len(), other.0.len());
        match (self.try_into_u64(), other.try_into_u64()) {
            (Some(a), Some(b)) => a.cmp(&b),
            // from the most significant word
            _ => self.words().rev().cmp(other.words().rev()),
        }
    }
}

impl PartialOrd for Scalar<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Hexadecimal, most significant byte first
impl Debug for Scalar<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;
        for byte in self.0.iter().rev() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Contiguous scalars of the same size, as little-endian bytes
#[derive(Clone, Copy, Debug)]
pub struct ScalarSlice<'a> {
    bytes: &'a [u8],
    size: ScalarSize,
}

impl<'a> ScalarSlice<'a> {
    pub fn new(bytes: &'a [u8], size: ScalarSize) -> Self {
        assert!(bytes.len().is_multiple_of(size.bytes()));
        Self { bytes, size }
    }

    pub fn size(&self) -> ScalarSize {
        self.size
    }

    /// The packed scalars, `len() * size().bytes()` little-endian bytes
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len() >> self.size as u8
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn get(&self, idx: usize) -> Scalar<'a> {
        self.try_get(idx).unwrap()
    }

    /// Build a sub-[ScalarSlice]
    pub fn slice(&self, start: usize, len: usize) -> Self {
        let byte_size = self.size.bytes();
        Self {
            bytes: &self.bytes[start * byte_size..][..len * byte_size],
            size: self.size,
        }
    }

    pub fn try_get(&self, idx: usize) -> Option<Scalar<'a>> {
        let byte_size = self.size.bytes();
        let start = idx.checked_mul(byte_size)?;
        let bytes = self.bytes.get(start..)?.get(..byte_size)?;
        Some(Scalar(bytes))
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = Scalar<'a>> + ExactSizeIterator {
        self.bytes.chunks_exact(self.size.bytes()).map(Scalar)
    }

    /// Index of the first scalar for which `pred` is false, the scalars must be partitioned
    pub fn partition_point(&self, pred: impl FnMut(Scalar<'_>) -> bool) -> usize {
        match self.size {
            ScalarSize::U8 => partition_point::<1>(self.bytes, pred),
            ScalarSize::U16 => partition_point::<2>(self.bytes, pred),
            ScalarSize::U32 => partition_point::<4>(self.bytes, pred),
            ScalarSize::U64 => partition_point::<8>(self.bytes, pred),
            ScalarSize::U128 => partition_point::<16>(self.bytes, pred),
            ScalarSize::U256 => partition_point::<32>(self.bytes, pred),
            ScalarSize::U512 => partition_point::<64>(self.bytes, pred),
        }
    }
}

fn partition_point<const N: usize>(
    bytes: &[u8],
    mut pred: impl FnMut(Scalar<'_>) -> bool,
) -> usize {
    let (scalars, rest) = bytes.as_chunks::<N>();
    debug_assert!(rest.is_empty());
    scalars.partition_point(|scalar| pred(Scalar(scalar)))
}
