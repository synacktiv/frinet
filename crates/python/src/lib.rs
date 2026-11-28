use std::{fs::File, ops::Range, panic};

use frinet_db::{
    db::Db,
    format::{Addr, Time},
    module_timeline::ModuleId,
};
use memmap2::Mmap;
use pyo3::{prelude::*, types::PyTuple};

use crate::error::{LoadError, panic_message};

mod bulk;
mod calltree;
mod error;
mod index;
mod memory;
mod register;
mod search;
mod task;
mod timeline;

#[pymodule(name = "native")]
mod py_module {
    use frinet_db::module_timeline::{self, ModuleId};

    #[pymodule_export]
    use super::{PyDbHandle, PyModuleInfo, module_at, modules, open, time_end};

    #[pymodule_export]
    use super::timeline::{timeline_distinct_modules_in_range, timeline_pixels};

    #[pymodule_export]
    const MODULE_MARKER_NONE: ModuleId = module_timeline::MODULE_MARKER_NONE;

    #[pymodule_export]
    const MODULE_MARKER_MIXED: ModuleId = module_timeline::MODULE_MARKER_MIXED;

    #[pymodule_export]
    use super::error::{Cancelled, FrinetError, LoadError, NativeError, NoValueIndex};

    #[pymodule_export]
    use super::bulk::PyArray;

    #[pymodule_export]
    use super::register::{
        PyRegisterInfo, PyRegisterValues, register_distinct_values, register_first_time_with,
        register_is_write_at, register_last_time_with, register_next_change,
        register_next_time_with, register_prev_change, register_prev_time_with,
        register_times_with, register_value_at, register_value_offsets, register_values_in,
        registers, registers_written_at,
    };

    #[pymodule_export]
    use super::memory::{
        memory_reads, memory_writes, next_memory_access, next_memory_read, next_memory_write,
        prev_memory_access, prev_memory_read, prev_memory_write, read_cstring, read_memory,
        read_memory_with_unknowns,
    };

    #[pymodule_export]
    use super::search::{PySearchMatches, search_regex_start, search_start, validate_regex};

    #[pymodule_export]
    use super::index::index_start;

    #[pymodule_export]
    use super::task::PyTask;

    #[pymodule_export]
    use super::calltree::{
        PyCalltree, PyCalltreeInfo, PyCalltreeSpan, calltree_ancestors, calltree_children,
        calltree_info, calltree_span, calltree_span_at, calltree_start, calltree_step_back_over,
        calltree_step_out, calltree_step_over,
    };
}

/// Handle on an open database
#[pyclass(name = "DbHandle", frozen)]
pub struct PyDbHandle {
    // Borrows `mmap`, dropped first (declaration order), only lent by `&self`
    db: Db<'static>,
    mmap: Mmap,
}

impl PyDbHandle {
    fn open(path: &str) -> PyResult<Self> {
        let file = File::open(path)?;

        // SAFETY: the file must not be modified while mapped, like any database
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };

        // SAFETY: the mapping doesn't move with `mmap` and outlives `db` (see drop order),
        // and `db` is only lent for a borrow of `self` (see `Self::db`)
        let bytes: &'static [u8] = unsafe { std::slice::from_raw_parts(mmap.as_ptr(), mmap.len()) };

        let db = panic::catch_unwind(|| {
            // A corrupted database panics while loading
            Db::from_aligned_slice(bytes)
        })
        .map_err(|payload| {
            LoadError::new_err(format!("corrupted database: {}", panic_message(&*payload)))
        })?
        .map_err(|err| LoadError::new_err(err.to_string()))?;

        Ok(Self { db, mmap })
    }

    pub(crate) fn db(&self) -> &Db<'_> {
        &self.db
    }

    /// Where `bytes`, borrowed from the database, sit in the mapping
    pub(crate) fn range_of(&self, bytes: &[u8]) -> Range<usize> {
        if bytes.is_empty() {
            return 0..0;
        }
        let start = (bytes.as_ptr() as usize)
            .checked_sub(self.mmap.as_ptr() as usize)
            .filter(|start| start + bytes.len() <= self.mmap.len())
            .expect("the bytes are borrowed from the mapping");
        start..start + bytes.len()
    }

    pub(crate) fn bytes(&self, range: Range<usize>) -> &[u8] {
        &self.mmap[range]
    }
}

/// Raises `OSError` if the file can't be read, [LoadError] if it is not a valid database
#[pyfunction]
fn open(path: &str) -> PyResult<PyDbHandle> {
    PyDbHandle::open(path)
}

/// End of the trace: time of its last event, the DB stops there
#[pyfunction]
fn time_end(handle: &PyDbHandle) -> Time {
    handle.db().metadata.time_end
}

/// A module of the trace header, mapped at `start..end` (`end` excluded)
#[pyclass(name = "Module", frozen, eq, hash, get_all)]
#[derive(PartialEq, Eq, Hash)]
pub struct PyModuleInfo {
    pub name: String,
    pub start: Addr,
    pub end: Addr,
}

#[pymethods]
impl PyModuleInfo {
    #[getter]
    fn size(&self) -> Addr {
        self.end - self.start
    }

    fn __contains__(&self, addr: i128) -> bool {
        (i128::from(self.start)..i128::from(self.end)).contains(&addr)
    }

    fn __repr__(&self) -> String {
        format!(
            "Module(name={:?}, start={:#x}, end={:#x})",
            self.name, self.start, self.end
        )
    }
}

/// In trace header order
#[pyfunction]
fn modules<'py>(py: Python<'py>, handle: &PyDbHandle) -> PyResult<Bound<'py, PyTuple>> {
    let modules = handle
        .db()
        .metadata
        .modules
        .iter()
        .map(|module| PyModuleInfo {
            name: module.name.clone(),
            start: module.start,
            end: module.end,
        });
    PyTuple::new(py, modules)
}

/// Find a module by address
#[pyfunction]
fn module_at(handle: &PyDbHandle, addr: Addr) -> Option<ModuleId> {
    handle.db().module_at(addr)
}
