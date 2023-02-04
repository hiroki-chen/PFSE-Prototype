use std::collections::HashMap;

use base64::{engine::general_purpose, Engine};
use num_traits::Num;
use rand::{distributions::Uniform, prelude::Distribution};
use rand_core::{OsRng, RngCore};

use crate::{
    fse::{AsBytes, FromBytes, Random},
    util::SizeAllocated,
};

pub mod lpfse;
pub mod native;
pub mod pfse;
pub mod wre;

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

impl FromBytes for String {
    #[inline(always)]
    fn from_bytes(bytes: &[u8]) -> Self {
        String::from_utf8(bytes.to_vec()).unwrap()
    }
}

impl FromBytes for i32 {
    #[inline(always)]
    fn from_bytes(bytes: &[u8]) -> Self {
        Self::from_ne_bytes(bytes.try_into().unwrap())
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

impl SizeAllocated for String {
    fn size_allocated(&self) -> usize {
        self.len()
    }
}

impl SizeAllocated for usize {
    fn size_allocated(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl SizeAllocated for u8 {
    fn size_allocated(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl SizeAllocated for u64 {
    fn size_allocated(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl<K, V> SizeAllocated for HashMap<K, V>
where
    K: SizeAllocated,
    V: SizeAllocated,
{
    fn size_allocated(&self) -> usize {
        self.iter()
            .map(|(k, v)| k.size_allocated() + v.size_allocated())
            .sum::<usize>()
    }
}

impl<T> SizeAllocated for Vec<T>
where
    T: SizeAllocated,
{
    fn size_allocated(&self) -> usize {
        self.iter().map(|e| e.size_allocated()).sum::<usize>()
    }
}

impl<T> SizeAllocated for [T]
where
    T: SizeAllocated,
{
    fn size_allocated(&self) -> usize {
        self.iter().map(|e| e.size_allocated()).sum::<usize>()
    }
}

impl<T, U> SizeAllocated for (T, U)
where
    T: SizeAllocated,
    U: SizeAllocated,
{
    fn size_allocated(&self) -> usize {
        self.0.size_allocated() + self.1.size_allocated()
    }
}
