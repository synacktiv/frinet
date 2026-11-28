//! Memory searches, run on a thread of their own

use frinet_db::{
    format::{Addr, Time},
    irange::IRange,
    search::{self as db_search, Pattern, SearchMatch},
};
use pyo3::prelude::*;

use crate::PyDbHandle;
use crate::error::{py_index_error, py_value_error};
use crate::task::{Failure, Output, PyTask, spawn};

/// What a search found, read one match at a time
#[pyclass(name = "SearchMatches", frozen, sequence)]
pub struct PySearchMatches(Vec<SearchMatch>);

#[pymethods]
impl PySearchMatches {
    fn __len__(&self) -> usize {
        self.0.len()
    }

    /// Address, size, and first and last times holding the match
    fn __getitem__(&self, index: usize) -> PyResult<(Addr, usize, Time, Time)> {
        let found = self
            .0
            .get(index)
            .ok_or_else(|| py_index_error("search match"))?;
        let addr = IRange::new(found.addr_min, found.addr_max);

        Ok((addr.min, addr.span_usize(), found.time_min, found.time_max))
    }
}

impl PySearchMatches {
    pub(crate) fn new(matches: Vec<SearchMatch>) -> Self {
        Self(matches)
    }
}

/// Searches `needle` in every memory snapshot of the trace
#[pyfunction]
pub fn search_start(handle: &Bound<'_, PyDbHandle>, needle: &[u8]) -> PyResult<PyTask> {
    Ok(spawn_search_task(
        handle,
        Pattern::literal(needle).map_err(py_value_error)?,
    ))
}

/// Searches a bytes regex in every memory snapshot of the trace
#[pyfunction]
pub fn search_regex_start(handle: &Bound<'_, PyDbHandle>, pattern: &str) -> PyResult<PyTask> {
    Ok(spawn_search_task(
        handle,
        Pattern::parse(pattern).map_err(py_value_error)?,
    ))
}

/// Validate a search regex pattern
#[pyfunction]
pub fn validate_regex(pattern: &str) -> PyResult<()> {
    Pattern::parse(pattern).map_err(py_value_error)?;
    Ok(())
}

fn spawn_search_task(handle: &Bound<'_, PyDbHandle>, pattern: Pattern) -> PyTask {
    let handle = handle.clone().unbind();

    spawn(move |task| {
        let matches = db_search::search_pattern(handle.get().db(), &pattern, task);
        if task.is_cancelled() {
            return Err(Failure::Cancelled);
        }
        Ok(Output::Matches(matches))
    })
}
