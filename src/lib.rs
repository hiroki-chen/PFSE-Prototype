#![allow(non_snake_case)]
#![allow(unused)]
#![deny(clippy::ptr_arg)]
#![deny(clippy::needless_borrow)]
#![deny(clippy::new_without_default)]
#![deny(clippy::needless_return)]
#![deny(clippy::unnecessary_to_owned)]

#[cfg(feature = "attack")]
pub mod attack;
pub mod db;
pub mod fse;
pub mod scheme;
pub mod util;

// Re-export
pub use scheme::*;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
