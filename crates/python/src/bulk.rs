//! Arrays of the DB, crossed without a copy through the buffer protocol

use std::ffi::{CStr, c_int, c_void};
use std::{ops::Range, ptr};

use pyo3::{exceptions::PyBufferError, ffi, prelude::*};

use crate::PyDbHandle;

/// Read-only view over an array of Scalars
#[pyclass(name = "Array", frozen)]
pub struct PyArray {
    handle: Py<PyDbHandle>,
    /// Of the items in the mapping
    range: Range<usize>,
    itemsize: usize,
    /// Struct format of the buffer items, bytes for the scalars wider than 8 bytes
    format: &'static CStr,
    buffer_itemsize: isize,
    buffer_len: isize,
}

impl PyArray {
    /// Over `bytes`, borrowed from the database of `handle`
    pub(crate) fn new(handle: &Bound<'_, PyDbHandle>, bytes: &[u8], itemsize: usize) -> Self {
        debug_assert!(itemsize > 0 && bytes.len().is_multiple_of(itemsize));
        let (format, buffer_itemsize) = match itemsize {
            2 => (c"H", 2),
            4 => (c"I", 4),
            8 => (c"Q", 8),
            _ => (c"B", 1),
        };
        Self {
            handle: handle.clone().unbind(),
            range: handle.get().range_of(bytes),
            itemsize,
            format,
            buffer_itemsize,
            buffer_len: (bytes.len() / buffer_itemsize as usize) as isize,
        }
    }
}

#[pymethods]
impl PyArray {
    #[getter]
    fn itemsize(&self) -> usize {
        self.itemsize
    }

    fn __len__(&self) -> usize {
        self.range.len() / self.itemsize
    }

    unsafe fn __getbuffer__(
        this: Bound<'_, Self>,
        view: *mut ffi::Py_buffer,
        flags: c_int,
    ) -> PyResult<()> {
        if view.is_null() {
            return Err(PyBufferError::new_err("view is null"));
        }
        if (flags & ffi::PyBUF_WRITABLE) == ffi::PyBUF_WRITABLE {
            return Err(PyBufferError::new_err("the DB is read only"));
        }

        let array = this.get();
        let bytes = array.handle.get().bytes(array.range.clone());
        let (buf, len) = (
            bytes.as_ptr().cast_mut().cast::<c_void>(),
            bytes.len() as isize,
        );
        let format = array.format.as_ptr().cast_mut();
        let shape = (&raw const array.buffer_len).cast_mut();
        let strides = (&raw const array.buffer_itemsize).cast_mut();
        let itemsize = array.buffer_itemsize;

        // SAFETY: `view` is not null, and `obj` keeps `this`, which `shape` and `strides` point
        // into, alive while the view is held
        unsafe {
            (*view).obj = this.into_any().into_ptr();
            (*view).buf = buf;
            (*view).len = len;
            (*view).readonly = 1;
            (*view).itemsize = itemsize;
            (*view).format = if (flags & ffi::PyBUF_FORMAT) == ffi::PyBUF_FORMAT {
                format
            } else {
                ptr::null_mut()
            };
            (*view).ndim = 1;
            (*view).shape = if (flags & ffi::PyBUF_ND) == ffi::PyBUF_ND {
                shape
            } else {
                ptr::null_mut()
            };
            (*view).strides = if (flags & ffi::PyBUF_STRIDES) == ffi::PyBUF_STRIDES {
                strides
            } else {
                ptr::null_mut()
            };
            (*view).suboffsets = ptr::null_mut();
            (*view).internal = ptr::null_mut();
        }

        Ok(())
    }
}
