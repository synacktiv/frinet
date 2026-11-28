use std::{
    fs::{File, OpenOptions},
    io,
    path::Path,
};

use memmap2::MmapMut;

pub trait StorageBackend {
    fn allocate(&mut self, size: usize) -> &mut [u8];
    fn truncate(&mut self, size: usize);
}

/// In-memory storage, aligned on 8 bytes
#[derive(Debug, Default, Clone)]
pub struct VecStorage {
    words: Vec<u64>,
    len: usize,
}

impl VecStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_bytes(&self) -> &[u8] {
        debug_assert!(self.len <= self.words.len() * 8);
        // SAFETY: in bounds, `u64` has no padding
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.len) }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        debug_assert!(self.len <= self.words.len() * 8);
        // SAFETY: in bounds, any byte pattern is a valid `u64`
        unsafe { std::slice::from_raw_parts_mut(self.words.as_mut_ptr().cast(), self.len) }
    }
}

impl StorageBackend for VecStorage {
    fn allocate(&mut self, size: usize) -> &mut [u8] {
        self.words = vec![0; size.div_ceil(8)];
        self.len = size;
        self.as_bytes_mut()
    }

    fn truncate(&mut self, size: usize) {
        assert!(self.len >= size);
        self.words.truncate(size.div_ceil(8));
        self.len = size;
    }
}

pub struct FileStorage {
    file: File,
    mmap: Option<MmapMut>,
}

impl FileStorage {
    /// Creates the database file, its size being set once the index is laid out
    pub fn create(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)?;

        Ok(Self { file, mmap: None })
    }
}

impl StorageBackend for FileStorage {
    fn allocate(&mut self, size: usize) -> &mut [u8] {
        self.file.set_len(size as _).unwrap();
        // SAFETY: the file is only reachable through this mapping
        self.mmap = Some(unsafe { MmapMut::map_mut(&self.file) }.unwrap());
        self.mmap.as_mut().unwrap()
    }

    fn truncate(&mut self, size: usize) {
        self.file.set_len(size as _).unwrap();
    }
}
