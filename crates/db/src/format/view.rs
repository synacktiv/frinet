use core::fmt::{self, Display};
use core::marker::PhantomData;

use crate::scalar::{ScalarSize, ScalarSlice};

use super::{Header, Pod, Section};

#[derive(Debug)]
pub enum LoadError {
    InvalidMagic,
    InvalidVersion {
        got: [u8; 8],
        expected: [u8; 8],
    },
    /// Too small to hold a header
    TooSmall,
}

impl Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::InvalidMagic => f.write_str("invalid magic"),
            LoadError::InvalidVersion { got, expected } => write!(
                f,
                "unexpected version, got:{} expected:{}",
                got.escape_ascii(),
                expected.escape_ascii()
            ),
            LoadError::TooSmall => f.write_str("database is too small"),
        }
    }
}

const HEADER: Section<Header> = Section::new(0, 1);

/// Read-only view over a database storage
#[derive(Clone, Copy)]
pub struct Storage<'s> {
    bytes: &'s [u8],
}

impl<'s> Storage<'s> {
    pub fn new(bytes: &'s [u8]) -> Self {
        Self { bytes }
    }

    pub fn header(&self) -> Result<&'s Header, LoadError> {
        if self.bytes.len() < HEADER.byte_range().end {
            return Err(LoadError::TooSmall);
        }
        Ok(&self.slice(HEADER)[0])
    }

    /// Panics if `section` is out-of-bounds
    pub fn scalar_slice(&self, section: Section<u8>, size: ScalarSize) -> ScalarSlice<'s> {
        ScalarSlice::new(self.slice(section), size)
    }

    /// Panics if `section` is out-of-bounds or misaligned
    pub fn slice<P: Pod>(&self, section: Section<P>) -> &'s [P] {
        if section.is_empty() {
            return &[];
        }

        let byte_range = &self.bytes[section.byte_range()];

        assert!(byte_range.as_ptr().cast::<P>().is_aligned());

        // SAFETY: bounds and alignment are checked, `P` is Pod
        unsafe { core::slice::from_raw_parts(byte_range.as_ptr().cast(), section.len()) }
    }
}

/// Mutable view over a database storage, used while building the database
pub struct StorageMut<'s> {
    ptr: *mut u8,
    len: usize,
    _storage: PhantomData<&'s mut [u8]>,
}

// SAFETY: behaves like `&'s mut [u8]`
unsafe impl Send for StorageMut<'_> {}
// SAFETY: every shared access goes through `unsafe` methods
unsafe impl Sync for StorageMut<'_> {}

impl<'s> StorageMut<'s> {
    pub fn new(bytes: &'s mut [u8]) -> Self {
        Self {
            ptr: bytes.as_mut_ptr(),
            len: bytes.len(),
            _storage: PhantomData,
        }
    }

    pub fn header(&self) -> &Header {
        // SAFETY: the header is only reachable through `header` and `header_mut`
        unsafe { &self.slice(HEADER)[0] }
    }

    pub fn header_mut(&mut self) -> &mut Header {
        // SAFETY: the header is only reachable through `header` and `header_mut`
        unsafe { &mut self.slice_mut(HEADER)[0] }
    }

    /// # Safety
    ///
    /// No mutable borrow overlapping `section` must be alive
    pub unsafe fn slice<P: Pod>(&self, section: Section<P>) -> &'s [P] {
        let ptr = self.section_ptr(section);
        // SAFETY: checked by `section_ptr`, aliasing is up to the caller
        unsafe { core::slice::from_raw_parts(ptr, section.len()) }
    }

    /// # Safety
    ///
    /// No other borrow overlapping `section` must be alive
    pub unsafe fn slice_mut<P: Pod>(&self, section: Section<P>) -> &'s mut [P] {
        let ptr = self.section_ptr(section);
        // SAFETY: checked by `section_ptr`, aliasing is up to the caller
        unsafe { core::slice::from_raw_parts_mut(ptr, section.len()) }
    }

    fn section_ptr<P: Pod>(&self, section: Section<P>) -> *mut P {
        if section.is_empty() {
            return core::ptr::NonNull::dangling().as_ptr();
        }

        let range = section.byte_range();
        assert!(range.end <= self.len);

        // SAFETY: in bounds
        let ptr = unsafe { self.ptr.add(range.start) }.cast::<P>();
        assert!(ptr.is_aligned());
        ptr
    }
}
