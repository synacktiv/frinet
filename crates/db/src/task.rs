//! Progress and cancellation of a long running query

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Progress and cancellation shared between a running query and whoever started it
#[derive(Debug, Default)]
pub struct Task {
    cancelled: AtomicBool,
    done: AtomicUsize,
    total: AtomicUsize,
}

impl Task {
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the query to stop between two units of work, it keeps what it already found
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Units of work done and total, `(0, 0)` before the query knows its total
    pub fn progress(&self) -> (usize, usize) {
        (
            self.done.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed),
        )
    }

    pub fn set_total(&self, total: usize) {
        self.total.store(total, Ordering::Relaxed);
    }

    /// Reports `count` more units of work done
    pub fn advance(&self, count: usize) {
        self.done.fetch_add(count, Ordering::Relaxed);
    }

    /// Reports the work done so far, for a query counting its own position
    pub fn set_done(&self, done: usize) {
        self.done.store(done, Ordering::Relaxed);
    }
}
