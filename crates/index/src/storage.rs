use std::{
    fs::{File, OpenOptions},
    path::PathBuf,
};

use memmap2::MmapMut;

pub trait DbStorage {
    fn allocate(&mut self, size: usize) -> &mut [u8];
    fn truncate(&mut self, size: usize);
}

impl DbStorage for Vec<u8> {
    fn allocate(&mut self, size: usize) -> &mut [u8] {
        self.clear();
        self.reserve_exact(size);
        unsafe { self.set_len(size) }; // SAFE ?
        self.as_mut_slice()
    }

    fn truncate(&mut self, size: usize) {
        assert!(self.len() >= size);
        self.resize(size, 0);
    }
}

pub struct OnDisk {
    path: PathBuf,
    file: Option<File>,
    mmap: Option<MmapMut>,
}

impl OnDisk {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            file: None,
            mmap: None,
        }
    }
}

impl DbStorage for OnDisk {
    fn allocate(&mut self, size: usize) -> &mut [u8] {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&self.path)
            .unwrap();
        file.set_len(size as _).unwrap();

        self.file = Some(file);
        let file = self.file.as_ref().unwrap();

        self.mmap = Some(unsafe { MmapMut::map_mut(file) }.unwrap());
        self.mmap.as_mut().unwrap()
    }

    fn truncate(&mut self, size: usize) {
        // Windows cannot resize a file while a mapped view is open (os error 1224):
        // flush and unmap first.
        if let Some(mmap) = self.mmap.take() {
            mmap.flush().unwrap();
            drop(mmap);
        }
        self.file.as_mut().unwrap().set_len(size as _).unwrap();
    }
}
