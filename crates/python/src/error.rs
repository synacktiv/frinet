//! The errors this package raises, and how the errors of Rust become Python ones

use std::{any::Any, fmt::Display};

use pyo3::{
    create_exception,
    exceptions::{PyException, PyIndexError, PyValueError},
    prelude::*,
};

create_exception!(
    native,
    FrinetError,
    PyException,
    "Base of the errors this package raises itself"
);
create_exception!(native, LoadError, FrinetError, "Invalid database");
create_exception!(
    native,
    Cancelled,
    FrinetError,
    "The result of work that was cancelled before it ended"
);
create_exception!(
    native,
    NativeError,
    FrinetError,
    "What work running on a Rust thread raised"
);
create_exception!(
    native,
    NoValueIndex,
    FrinetError,
    "A register the indexer did not index by value"
);

/// What Python refuses, as a `ValueError`
pub(crate) fn py_value_error(err: impl Display) -> PyErr {
    PyValueError::new_err(err.to_string())
}

/// A query by value on the register `name`, which the indexer did not index by value
pub(crate) fn py_no_value_index(name: &str) -> PyErr {
    NoValueIndex::new_err(format!("the register '{name}' is not indexed by value"))
}

/// An index past the end of the `what` items, as an `IndexError`
pub(crate) fn py_index_error(what: &str) -> PyErr {
    PyIndexError::new_err(format!("{what} index out of range"))
}

pub(crate) fn panic_message(payload: &(dyn Any + Send)) -> &str {
    if let Some(msg) = payload.downcast_ref::<&str>() {
        msg
    } else if let Some(msg) = payload.downcast_ref::<String>() {
        msg
    } else {
        "unknown panic"
    }
}
