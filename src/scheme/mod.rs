use base64::{engine::general_purpose, Engine};
use rand_core::{OsRng, RngCore};

use crate::fse::Random;

pub mod lpfse;
pub mod pfse;

impl Random for String {
    fn random(len: usize) -> Self {
        let mut buffer = Vec::new();
        buffer.resize(len, 0u8);
        OsRng.fill_bytes(&mut buffer);
        general_purpose::STANDARD_NO_PAD.encode(buffer)
    }
}
