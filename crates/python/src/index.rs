//! Building a database from a trace file

use std::fs;
use std::path::PathBuf;

use frinet_db::task::Task;
use frinet_index::parser::{Pass, ProgressReporter};
use frinet_index::{build_index, parser::TraceFile, storage::FileStorage};
use pyo3::prelude::*;

use crate::task::{Failure, Output, PyTask, spawn};

/// Indexes `trace_path` into `db_path`, removing the database if it does not end well
#[pyfunction]
#[pyo3(signature = (trace_path, db_path, node_size_order = 3))]
pub fn index_start(trace_path: PathBuf, db_path: PathBuf, node_size_order: u8) -> PyResult<PyTask> {
    let mut parser = TraceFile::open(&trace_path)?;
    let mut storage = FileStorage::create(&db_path)?;

    Ok(spawn(move |task| {
        let mut reporter = Reporter {
            task,
            pass: 0,
            pass_len: 0,
        };
        let built = build_index(&mut parser, &mut reporter, &mut storage, node_size_order);
        drop(storage);

        let result = match built {
            Ok(true) => return Ok(Output::Nothing),
            Ok(false) => Err(Failure::Cancelled),
            Err(err) => Err(Failure::Error(err.to_string())),
        };
        let _ = fs::remove_file(&db_path);
        result
    }))
}

/// Every pass reads the whole trace: the passes add up into one progress
struct Reporter<'t> {
    task: &'t Task,
    pass: usize,
    pass_len: usize,
}

impl ProgressReporter for Reporter<'_> {
    fn start(&mut self, pass: Pass) {
        self.pass = pass as usize;
    }

    fn total(&mut self, total: usize) {
        self.pass_len = total;
        self.task.set_total(3 * total);
        self.task.set_done(self.pass * total);
    }

    fn current(&mut self, current: usize) {
        self.task.set_done(self.pass * self.pass_len + current);
    }

    fn is_cancelled(&self) -> bool {
        self.task.is_cancelled()
    }
}
