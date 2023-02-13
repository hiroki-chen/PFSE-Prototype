//! This module mainly defines a trait called `FrequencySmoothing` that should be implemented for any struct that tries to act like `FSE`.

use std::{f64::consts::E, fmt::Debug, fs::File, io::Write};

use itertools::Itertools;
use log::{debug, error};
use mongodb::bson::Document;

use crate::{
    db::{Connector, Data},
    util::SizeAllocated,
};

pub type HistType<T> = (T, usize);
pub type FreqType<T> = (T, f64);
pub type ValueType = (usize, usize, usize);

impl SizeAllocated for ValueType {
    fn size_allocated(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

pub const DEFAULT_RANDOM_LEN: usize = 32usize;

/// Since we do not know the concret type of `T`, we need an extra trait to require that
/// `T` can be randomly sampled.
pub trait Random {
    fn random(len: usize) -> Self;
}

/// A trait that defines `as_bytes` method.
pub trait AsBytes {
    fn as_bytes(&self) -> &[u8];
}

/// A trait that defines `from_bytes` method.
pub trait FromBytes {
    fn from_bytes(bytes: &[u8]) -> Self;
}

/// A trait that defines conector method.
pub trait Conn {
    fn get_conn(&self) -> &Connector<Data>;
}

/// This trait defines the interfaces for any cryptographic schemes.

pub trait BaseCrypto<T>: Debug + Conn + SizeAllocated
where
    T: AsBytes + FromBytes + Debug,
{
    /// Given a security parameter, generate a secret key.
    fn key_generate(&mut self);

    /// Encrypt the message and return the ciphertext vector. Return `None` if error occurrs.
    fn encrypt(&mut self, message: &T) -> Option<Vec<Vec<u8>>>;

    /// Decrypt the ciphertext and return the plaintext. Return `None` if error occurrs.
    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>>;

    /// Store the summary of the current context into a given file.
    fn store(&self, path: &str) -> std::io::Result<()> {
        let mut file = File::create(path)?;
        write!(
            &mut file,
            "Summary of the current context is\n\t{:#?}",
            self
        )
    }

    fn search_impl(
        &self,
        ciphertexts: Vec<Vec<u8>>,
        name: &str,
    ) -> Option<Vec<T>> {
        debug!("Generated {} tokens.", ciphertexts.len());

        let query_result = ciphertexts
            .into_iter()
            .map(|e| {
                let mut document = Document::new();
                document
                    .insert("data".to_string(), String::from_utf8(e).unwrap());
                document
            })
            .collect::<Vec<_>>();

        let mut res = Vec::new();
        for encrypted_message in query_result.chunks(4096) {
            let mut filter = Document::new();
            filter.insert("$or", encrypted_message);

            let data = match self.get_conn().search(filter, name) {
                Ok(cursor) => cursor,
                Err(e) => {
                    error!("Error: {:?}", e);
                    return None;
                }
            }
            .into_iter()
            .map(|data| {
                let message_bytes = self
                    .decrypt(data.unwrap().data.as_bytes())
                    .unwrap_or_default();
                T::from_bytes(&message_bytes)
            })
            .collect::<Vec<_>>();

            res.push(data);
        }
        debug!("Matched document: {}.", res.len());

        Some(res.into_iter().flatten().collect())
    }

    /// Search a given message `T` from the remote server.
    fn search(&mut self, message: &T, name: &str) -> Option<Vec<T>> {
        let ciphertexts = match self.encrypt(message) {
            Some(v) => v,
            None => return None,
        };
        debug!("Ciphertext size = {}", ciphertexts.len());
        self.search_impl(ciphertexts, name)
    }
}

/// This trait is derived from [`FrequencySmoothing`] for partition-based FSE schemes.
pub trait PartitionFrequencySmoothing<T>: BaseCrypto<T>
where
    T: AsBytes + FromBytes + Debug,
{
    /// Initialize all the parameters.
    fn set_params(&mut self, params: &[f64]);

    /// Given a vector of `T` and a function closure as the partitioning function, this function constructs the partitioned vectors
    /// containing tuples `(T, usize)` (T and its count).
    fn partition(&mut self, input: &[T], partition_func: fn(f64, usize) -> f64);

    /// Transform each partition by duplicating and smoothing each message.
    fn transform(&mut self);

    /// Smoothes the partitions and outputs the ciphertext set.
    fn smooth(&mut self) -> Vec<Vec<u8>>;
}

/// A function used in the partition phase. It takes the form `f(x) = \lambda e^{-\lambda x}`.
pub fn exponential(param: f64, x: usize) -> f64 {
    param * E.powf(-param * (x - 1) as f64)
}
