//! On-disk format of the indexed database

mod layout;
mod types;
mod view;

pub use layout::*;
pub use types::*;
pub use view::*;

pub const DB_MAGIC: [u8; 8] = *b"FDBv001\0";
