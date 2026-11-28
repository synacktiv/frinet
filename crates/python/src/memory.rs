//! Memory content and accesses over the `size` bytes at `addr`

use frinet_db::{
    db::Db,
    format::{Addr, MemNode, Time},
    irange::IRange,
};
use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};

use crate::PyDbHandle;

/// Largest read, the content being built in memory
const READ_MAX: i128 = 1 << 30;

/// Address, size, and time of the read, or time of the write and last time its bytes are there
type Event = (Addr, usize, Time, Time);

/// Memory content at `time`, the bytes the trace does not know read as zero
#[pyfunction]
pub fn read_memory<'py>(
    py: Python<'py>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    size: i128,
) -> PyResult<Bound<'py, PyBytes>> {
    let db = handle.db();
    let range = read_range(addr, size)?;
    let data = py.detach(|| db.read_memory(range, time));
    Ok(PyBytes::new(py, &data))
}

/// Memory content at `time`, `None` for the bytes the trace does not know
#[pyfunction]
pub fn read_memory_with_unknowns(
    py: Python<'_>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    size: i128,
) -> PyResult<Vec<Option<u8>>> {
    let db = handle.db();
    let range = read_range(addr, size)?;
    Ok(py.detach(|| db.read_memory_with_unknowns(range, time)))
}

/// Bytes at `time` up to the first zero, stopping on the first unknown byte
#[pyfunction]
pub fn read_cstring<'py>(
    py: Python<'py>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    max_size: i128,
) -> PyResult<Bound<'py, PyBytes>> {
    let db = handle.db();
    let range = read_range(addr, max_size)?;
    let content = py.detach(|| db.read_memory_with_unknowns(range, time));
    let string: Vec<u8> = content
        .into_iter()
        .map_while(|byte| byte.filter(|byte| *byte != 0))
        .collect();
    Ok(PyBytes::new(py, &string))
}

/// Reads done by the instruction at `time`
#[pyfunction]
pub fn memory_reads(
    py: Python<'_>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    size: i128,
) -> PyResult<Vec<Event>> {
    let db = handle.db();
    let query = point_query(time, addr_range(addr, size)?);

    Ok(py.detach(|| {
        db.mem_read_intersects(query)
            .map(|leaf| {
                let addr = leaf.addr;
                (addr.min, addr.span_usize(), leaf.time, leaf.time)
            })
            .collect()
    }))
}

/// Writes done by the instruction at `time`
#[pyfunction]
pub fn memory_writes(
    py: Python<'_>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    size: i128,
) -> PyResult<Vec<Event>> {
    let db = handle.db();
    let query = point_query(time, addr_range(addr, size)?);

    Ok(py.detach(|| {
        db.mem_write_intersects(query)
            .filter(|leaf| leaf.node.time.min == time)
            .map(|leaf| {
                let (addr, time) = (leaf.node.addr, leaf.node.time);
                (addr.min, addr.span_usize(), time.min, time.max)
            })
            .collect()
    }))
}

/// Nearest read strictly before `time`
#[pyfunction]
pub fn prev_memory_read(
    py: Python<'_>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    size: i128,
) -> PyResult<Option<Time>> {
    nearest(py, handle, time, addr, size, |db, time, range| {
        db.prev_mem_read(time, range)
    })
}

/// Nearest read strictly after `time`
#[pyfunction]
pub fn next_memory_read(
    py: Python<'_>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    size: i128,
) -> PyResult<Option<Time>> {
    nearest(py, handle, time, addr, size, |db, time, range| {
        db.next_mem_read(time, range)
    })
}

/// Nearest write strictly before `time`
#[pyfunction]
pub fn prev_memory_write(
    py: Python<'_>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    size: i128,
) -> PyResult<Option<Time>> {
    nearest(py, handle, time, addr, size, |db, time, range| {
        db.prev_mem_write(time, range)
    })
}

/// Nearest write strictly after `time`
#[pyfunction]
pub fn next_memory_write(
    py: Python<'_>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    size: i128,
) -> PyResult<Option<Time>> {
    nearest(py, handle, time, addr, size, |db, time, range| {
        db.next_mem_write(time, range)
    })
}

/// Nearest read or content update strictly before `time`
#[pyfunction]
pub fn prev_memory_access(
    py: Python<'_>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    size: i128,
) -> PyResult<Option<Time>> {
    nearest(py, handle, time, addr, size, |db, time, range| {
        db.prev_mem_access(time, range)
    })
}

/// Nearest read or content update strictly after `time`
#[pyfunction]
pub fn next_memory_access(
    py: Python<'_>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    size: i128,
) -> PyResult<Option<Time>> {
    nearest(py, handle, time, addr, size, |db, time, range| {
        db.next_mem_access(time, range)
    })
}

fn nearest(
    py: Python<'_>,
    handle: &PyDbHandle,
    time: Time,
    addr: i128,
    size: i128,
    query: impl FnOnce(&Db<'_>, Time, IRange<Addr>) -> Option<Time> + Send,
) -> PyResult<Option<Time>> {
    let db = handle.db();
    let range = addr_range(addr, size)?;
    Ok(py.detach(|| query(db, time, range)))
}

/// The range of a read, raising `ValueError` past a gibibyte
fn read_range(addr: i128, size: i128) -> PyResult<IRange<Addr>> {
    if size > READ_MAX {
        let message = format!("{size} bytes is more than the gibibyte a read builds");
        return Err(PyValueError::new_err(message));
    }
    addr_range(addr, size)
}

/// The `size` bytes at `addr`, raising `ValueError` outside the address space
fn addr_range(addr: i128, size: i128) -> PyResult<IRange<Addr>> {
    if size <= 0 {
        return Err(PyValueError::new_err(format!(
            "size must be positive, got {size}"
        )));
    }
    if addr < 0 || addr + size > 1 << 64 {
        let sign = if addr < 0 { "-" } else { "" };
        let addr = addr.unsigned_abs();
        return Err(PyValueError::new_err(format!(
            "{size} bytes at {sign}{addr:#x} are out of the address space"
        )));
    }
    Ok(IRange::new(addr as Addr, (addr + size - 1) as Addr))
}

fn point_query(time: Time, addr: IRange<Addr>) -> MemNode {
    MemNode {
        addr,
        time: IRange::one(time),
    }
}
