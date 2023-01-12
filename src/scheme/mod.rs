use base64::{engine::general_purpose, Engine};
use num_traits::Num;
use rand::{distributions::Uniform, prelude::Distribution};
use rand_core::{OsRng, RngCore};

use crate::fse::{AsBytes, Random};

pub mod lpfse;
pub mod naive;
pub mod pfse;

impl Random for i32 {
    #[inline(always)]
    fn random(_len: usize) -> Self {
        Uniform::new_inclusive(0, Self::MAX).sample(&mut OsRng)
    }
}

impl Random for String {
    fn random(len: usize) -> Self {
        let mut buffer = Vec::new();
        buffer.resize(len, 0u8);
        OsRng.fill_bytes(&mut buffer);
        general_purpose::STANDARD_NO_PAD.encode(buffer)
    }
}

impl AsBytes for String {
    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsBytes for i32 {
    /// Return the memory representation of this number as a byte array in
    /// native byte order.
    #[inline(always)]
    fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self.to_ne_bytes().as_ptr(),
                std::mem::size_of::<Self>(),
            )
        }
    }
}
