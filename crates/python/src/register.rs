//! Register values and searches, registers are indexed in trace header order

use frinet_db::{
    db::Db,
    format::{Time, slice_of},
    register::Register,
    scalar::Scalar,
    time_series::{SeriesByValue, TimeSearch},
};
use pyo3::{
    exceptions::{PyOverflowError, PyValueError},
    prelude::*,
    types::PyInt,
};
use std::ops::RangeInclusive;

use crate::error::{py_index_error, py_no_value_index};
use crate::{PyDbHandle, bulk::PyArray};

/// Register of the trace header
#[pyclass(name = "RegisterInfo", frozen, get_all)]
pub struct PyRegisterInfo {
    /// Trace header order, the first register is the PC
    pub index: usize,
    pub name: String,
    pub byte_size: usize,
    /// First write ..= end of the trace, [None] if the register is never written
    pub time_range: Option<(Time, Time)>,
    /// Whether the `*_time_with` searches work on this register
    pub value_indexed: bool,
}

/// In trace header order
#[pyfunction]
pub fn registers(handle: &PyDbHandle) -> Vec<PyRegisterInfo> {
    let trace = handle.db();

    trace
        .metadata
        .registers
        .iter()
        .zip(trace.registers())
        .enumerate()
        .map(|(index, (info, register))| PyRegisterInfo {
            index,
            name: info.name.clone(),
            byte_size: info.scalar_size.bytes(),
            time_range: register.time_range().map(|range| (range.min, range.max)),
            value_indexed: register.has_by_value_index(),
        })
        .collect()
}

/// Value of the register at `time`, [None] if it has none
#[pyfunction]
pub fn register_value_at(
    py: Python<'_>,
    handle: &PyDbHandle,
    index: usize,
    time: Time,
) -> PyResult<Option<Py<PyInt>>> {
    match register(handle.db(), index)?.value_at(time) {
        None => Ok(None),
        Some(value) => Ok(Some(scalar_into_py_int(py, value)?.unbind())),
    }
}

/// The value of the register at every step of a time range, read one chunk at a time
#[pyclass(name = "RegisterValues")]
pub struct PyRegisterValues {
    handle: Py<PyDbHandle>,
    index: usize,
    /// The steps left to read
    times: RangeInclusive<Time>,
}

#[pymethods]
impl PyRegisterValues {
    /// The values of the next `size` steps at most, empty once every step is read
    fn next_chunk(&mut self, py: Python<'_>, size: usize) -> PyResult<Vec<Option<Py<PyInt>>>> {
        let register = register(self.handle.get().db(), self.index)?;
        self.times
            .by_ref()
            .take(size)
            .map(|time| {
                register
                    .value_at(time)
                    .map(|value| Ok(scalar_into_py_int(py, value)?.unbind()))
                    .transpose()
            })
            .collect()
    }
}

/// The value at every step of `time_min..=time_max`, [None] for the steps holding none
#[pyfunction]
pub fn register_values_in(
    handle: &Bound<'_, PyDbHandle>,
    index: usize,
    time_min: Time,
    time_max: Time,
) -> PyResult<PyRegisterValues> {
    if time_min > time_max {
        return Err(PyValueError::new_err(
            "the time range ends before it starts",
        ));
    }

    register(handle.get().db(), index)?;

    Ok(PyRegisterValues {
        handle: handle.clone().unbind(),
        index,
        times: time_min..=time_max,
    })
}

/// Whether the instruction at `time` wrote the register
#[pyfunction]
pub fn register_is_write_at(handle: &PyDbHandle, index: usize, time: Time) -> PyResult<bool> {
    Ok(register(handle.db(), index)?.is_write_at(time))
}

/// One flag per register in trace header order, for the instruction at `time`
#[pyfunction]
pub fn registers_written_at(handle: &PyDbHandle, time: Time) -> Vec<bool> {
    handle
        .db()
        .registers()
        .iter()
        .map(|register| register.is_write_at(time))
        .collect()
}

/// Last time before `time` holding another value
#[pyfunction]
pub fn register_prev_change(
    handle: &PyDbHandle,
    index: usize,
    time: Time,
) -> PyResult<Option<Time>> {
    Ok(register(handle.db(), index)?.prev_change(time))
}

/// First time after `time` holding another value
#[pyfunction]
pub fn register_next_change(
    handle: &PyDbHandle,
    index: usize,
    time: Time,
) -> PyResult<Option<Time>> {
    Ok(register(handle.db(), index)?.next_change(time))
}

#[pyfunction]
pub fn register_first_time_with(
    handle: &PyDbHandle,
    index: usize,
    value: &Bound<'_, PyInt>,
) -> PyResult<Option<Time>> {
    find_time_with(handle, index, TimeSearch::First, value)
}

#[pyfunction]
pub fn register_last_time_with(
    handle: &PyDbHandle,
    index: usize,
    value: &Bound<'_, PyInt>,
) -> PyResult<Option<Time>> {
    find_time_with(handle, index, TimeSearch::Last, value)
}

/// Nearest write of `value` strictly before `time`
#[pyfunction]
pub fn register_prev_time_with(
    handle: &PyDbHandle,
    index: usize,
    value: &Bound<'_, PyInt>,
    time: Time,
) -> PyResult<Option<Time>> {
    find_time_with(handle, index, TimeSearch::Before(time), value)
}

/// Nearest write of `value` strictly after `time`
#[pyfunction]
pub fn register_next_time_with(
    handle: &PyDbHandle,
    index: usize,
    value: &Bound<'_, PyInt>,
    time: Time,
) -> PyResult<Option<Time>> {
    find_time_with(handle, index, TimeSearch::After(time), value)
}

/// Every write time of `value`, sorted
#[pyfunction]
pub fn register_times_with(
    handle: &Bound<'_, PyDbHandle>,
    index: usize,
    value: &Bound<'_, PyInt>,
) -> PyResult<PyArray> {
    array(handle, index, |series| {
        let times = match py_int_to_scalar_bytes(value, series.values.size().bytes())? {
            Some(bytes) => series.times_of(Scalar(&bytes)),
            // wider than the register: it never held that value
            None => &[],
        };
        Ok((slice_of(times), size_of::<Time>()))
    })
}

/// Every value the register ever held, sorted
#[pyfunction]
pub fn register_distinct_values(handle: &Bound<'_, PyDbHandle>, index: usize) -> PyResult<PyArray> {
    array(handle, index, |series| {
        Ok((series.values.as_bytes(), series.values.size().bytes()))
    })
}

/// Write count of the `n`-th [register_distinct_values] is `offsets[n + 1] - offsets[n]`
#[pyfunction]
pub fn register_value_offsets(handle: &Bound<'_, PyDbHandle>, index: usize) -> PyResult<PyArray> {
    array(handle, index, |series| {
        Ok((slice_of(series.offsets), size_of::<u64>()))
    })
}

fn register<'db>(trace: &'db Db<'db>, index: usize) -> PyResult<&'db Register<'db>> {
    trace
        .register_by_index(index)
        .ok_or_else(|| py_index_error("register"))
}

/// The by value index of the register, raising `NoValueIndex` without one
fn by_value<'db>(trace: &'db Db<'db>, index: usize) -> PyResult<SeriesByValue<'db>> {
    register(trace, index)?
        .by_value
        .ok_or_else(|| py_no_value_index(&trace.metadata.registers[index].name))
}

/// Picks an array of the by value index, which the result keeps the mapping alive for
fn array(
    handle: &Bound<'_, PyDbHandle>,
    index: usize,
    pick: impl for<'db> FnOnce(SeriesByValue<'db>) -> PyResult<(&'db [u8], usize)>,
) -> PyResult<PyArray> {
    let (bytes, itemsize) = pick(by_value(handle.get().db(), index)?)?;
    Ok(PyArray::new(handle, bytes, itemsize))
}

fn find_time_with(
    handle: &PyDbHandle,
    index: usize,
    search: TimeSearch,
    value: &Bound<'_, PyInt>,
) -> PyResult<Option<Time>> {
    let series = by_value(handle.db(), index)?;

    let Some(bytes) = py_int_to_scalar_bytes(value, series.values.size().bytes())? else {
        return Ok(None);
    };

    Ok(series.find_time_with(search, Scalar(&bytes)))
}

/// `value` as `byte_size` little-endian bytes, [None] if it does not fit
fn py_int_to_scalar_bytes(value: &Bound<'_, PyInt>, byte_size: usize) -> PyResult<Option<Vec<u8>>> {
    if byte_size <= size_of::<u64>() {
        let Ok(value) = value.extract::<u64>() else {
            return Ok(None);
        };
        let bytes = value.to_le_bytes();
        let (kept, rest) = bytes.split_at(byte_size);
        if rest.iter().any(|byte| *byte != 0) {
            return Ok(None);
        }
        return Ok(Some(kept.to_vec()));
    }

    // above 64 bits, CPython does the conversion
    match value.call_method1("to_bytes", (byte_size, "little")) {
        Ok(bytes) => Ok(Some(bytes.extract()?)),
        Err(err) if err.is_instance_of::<PyOverflowError>(value.py()) => Ok(None),
        Err(err) => Err(err),
    }
}

/// Python `int`: native up to 64 bits, `int.from_bytes` above
fn scalar_into_py_int<'py>(py: Python<'py>, value: Scalar<'_>) -> PyResult<Bound<'py, PyInt>> {
    match value.try_into_u64() {
        Some(value) => Ok(value.into_pyobject(py)?),
        None => {
            let py_int = py.get_type::<PyInt>();
            Ok(py_int
                .call_method1("from_bytes", (value.0, "little"))?
                .cast_into::<PyInt>()?)
        }
    }
}
