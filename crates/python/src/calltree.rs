use frinet_db::{
    calltree::{self as db_calltree, Calltree, NO_PARENT, Points},
    format::{Addr, Time},
};
use pyo3::prelude::*;

use crate::PyDbHandle;
use crate::error::py_index_error;
use crate::task::{Failure, Output, PyTask, spawn};

#[pyclass(name = "Calltree", frozen)]
pub struct PyCalltree(pub(crate) Calltree);

#[pyclass(name = "CalltreeInfo", frozen, get_all)]
pub struct PyCalltreeInfo {
    pub span_count: usize,
    pub complete: bool,
}

/// A call: the time the trace spends inside a function. See `Calltree.span`.
#[pyclass(name = "CalltreeSpan", frozen, eq, hash, get_all)]
#[derive(PartialEq, Eq, Hash)]
pub struct PyCalltreeSpan {
    pub index: u32,
    /// Called address, or the first one of the trace for the span holding it
    pub entrypoint: Addr,
    pub time_range: (Time, Time),
    pub parent: Option<u32>,
    pub has_children: bool,
    /// Number of ancestors, 0 for a root
    pub depth: usize,
    /// The descendants are the spans after `index` up to this one, excluded
    pub subtree_end: u32,
}

#[pymethods]
impl PyCalltreeSpan {
    fn __repr__(&self) -> String {
        format!(
            "CalltreeSpan(index={}, entrypoint={:#x}, time_range={:?}, depth={})",
            self.index, self.entrypoint, self.time_range, self.depth
        )
    }
}

/// Builds the call tree from the times the PC reaches the points, away from the GIL
#[pyfunction]
pub fn calltree_start(
    handle: &Bound<'_, PyDbHandle>,
    entries: Vec<Addr>,
    exits: Vec<Addr>,
    calls: Vec<(Addr, Addr)>,
) -> PyTask {
    let handle = handle.clone().unbind();
    let points = Points {
        entries,
        exits,
        calls,
    };

    spawn(move |task| {
        db_calltree::build(handle.get().db(), &points, task)
            .map(Output::Tree)
            .ok_or(Failure::Cancelled)
    })
}

#[pyfunction]
pub fn calltree_info(tree: &PyCalltree) -> PyCalltreeInfo {
    PyCalltreeInfo {
        span_count: tree.0.spans.len(),
        complete: tree.0.complete,
    }
}

#[pyfunction]
pub fn calltree_span(tree: &PyCalltree, index: u32) -> PyResult<PyCalltreeSpan> {
    let span = span(tree, index)?;
    Ok(PyCalltreeSpan {
        index,
        entrypoint: span.entrypoint,
        time_range: (span.time_min, span.time_max),
        parent: (span.parent != NO_PARENT).then_some(span.parent),
        has_children: tree.0.has_children(index),
        depth: tree.0.depth(index),
        subtree_end: span.subtree_end,
    })
}

#[pyfunction]
#[pyo3(signature = (tree, index=None))]
pub fn calltree_children(tree: &PyCalltree, index: Option<u32>) -> PyResult<Vec<u32>> {
    if let Some(index) = index {
        span(tree, index)?;
    }
    Ok(tree.0.children(index).collect())
}

#[pyfunction]
pub fn calltree_span_at(tree: &PyCalltree, time: Time) -> Option<u32> {
    tree.0.span_at(time)
}

#[pyfunction]
pub fn calltree_ancestors(tree: &PyCalltree, index: u32) -> PyResult<Vec<u32>> {
    span(tree, index)?;
    Ok(tree.0.ancestors(index))
}

#[pyfunction]
pub fn calltree_step_over(tree: &PyCalltree, time: Time) -> Time {
    tree.0.step_over(time)
}

#[pyfunction]
pub fn calltree_step_back_over(tree: &PyCalltree, time: Time) -> Time {
    tree.0.step_back_over(time)
}

#[pyfunction]
pub fn calltree_step_out(tree: &PyCalltree, time: Time) -> Time {
    tree.0.step_out(time)
}

fn span(tree: &PyCalltree, index: u32) -> PyResult<&db_calltree::Span> {
    tree.0.span(index).ok_or_else(|| py_index_error("span"))
}
