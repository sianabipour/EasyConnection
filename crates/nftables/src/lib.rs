//! Isolated `table inet easy` ownership. Never edits other tables.

mod apply;
mod error;

pub use apply::{apply_table, flush_table, nft_bin, render_table, restore};
pub use error::NftError;

pub type Result<T> = std::result::Result<T, NftError>;
