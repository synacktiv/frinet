//! What the timeline of the IDA plugin draws: the module the PC runs in over time, read from
//! the module register

use frinet_db::{
    format::Time,
    module_timeline::{MODULE_MARKER_MIXED, MODULE_MARKER_NONE, ModuleId},
    register::Register,
};
use pyo3::{exceptions::PyValueError, prelude::*};

use crate::PyDbHandle;

/// The module of each of `pixels` equal slices of `time_min..=time_max`, or
/// [MODULE_MARKER_MIXED] if the PC changes of module during the slice
///
/// A slice has at least one step: with more pixels than steps, the pixels share them.
#[pyfunction]
pub fn timeline_pixels(
    handle: &PyDbHandle,
    time_min: Time,
    time_max: Time,
    pixels: usize,
) -> PyResult<Vec<ModuleId>> {
    check_time_range(time_min, time_max)?;
    let register = handle.db().module_register();
    let steps = u128::from(time_max - time_min) + 1;
    let pixel_start = |pixel: usize| time_min + (pixel as u128 * steps / pixels as u128) as Time;

    // first change after the start of the pixel, kept while it is ahead
    let mut change = register.next_change(time_min);

    Ok((0..pixels)
        .map(|pixel| {
            let start = pixel_start(pixel);
            let end = pixel_start(pixel + 1).max(start + 1);

            if change.is_some_and(|change| change <= start) {
                change = register.next_change(start);
            }
            if change.is_some_and(|change| change < end) {
                change = register.next_change(end - 1);
                MODULE_MARKER_MIXED
            } else {
                module_at(register, start)
            }
        })
        .collect())
}

/// Every module the PC runs in during `time_min..=time_max`, sorted
#[pyfunction]
pub fn timeline_distinct_modules_in_range(
    handle: &PyDbHandle,
    time_min: Time,
    time_max: Time,
) -> PyResult<Vec<ModuleId>> {
    check_time_range(time_min, time_max)?;
    let register = handle.db().module_register();

    let mut modules = vec![module_at(register, time_min)];
    let mut time = time_min;
    while let Some(change) = register.next_change(time)
        && change <= time_max
    {
        modules.push(module_at(register, change));
        time = change;
    }

    modules.sort_unstable();
    modules.dedup();
    Ok(modules)
}

fn module_at(register: &Register<'_>, time: Time) -> ModuleId {
    register
        .value_at(time)
        .and_then(|value| value.try_into_u64())
        .map_or(MODULE_MARKER_NONE, |module| module as ModuleId)
}

fn check_time_range(time_min: Time, time_max: Time) -> PyResult<()> {
    if time_min > time_max {
        return Err(PyValueError::new_err(
            "the time range ends before it starts",
        ));
    }
    Ok(())
}
