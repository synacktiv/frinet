//! Register indexes:
//! - by time: value at a given time (chunks of a sparse or a dense encoding), every register
//! - by value: write times of a given value (inverted index), the PC only
//!
//! One sample per write: the tracer only emits a register when its value changes (the PC is
//! emitted at every step), so no deduplication is done while indexing.

mod by_time;
mod by_value;

pub use by_time::*;
pub use by_value::*;
