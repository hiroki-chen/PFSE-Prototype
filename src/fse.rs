//! This module mainly defines a trait called `FrequencySmoothing` that should be implemented for any struct that tries to act like `FSE`.

use std::{f64::consts::E, fmt::Debug, fs::File, io::Write};

pub type HistType<T> = (T, usize);
pub type FreqType<T> = (T, f64);
pub type ValueType = (usize, usize, usize);

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

/// This trait defines the interfaces for any cryptographic schemes.

pub trait SymmetricEncryption<T>: Debug
where
    T: AsBytes + Debug,
{
    /// Given a security parameter, generate a secret key.
    fn key_generate(&mut self);

    /// Encrypt the message and return the ciphertext vector. Return `None` if error occurrs.
    fn encrypt(&self, message: &T) -> Option<Vec<Vec<u8>>>;

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

    /// Search a given message `T` from the remote server.
    fn search(&self, _message: &T) -> Option<Vec<T>> {
        unimplemented!()
    }
}

/// This trait is derived from [`FrequencySmoothing`] for partition-based FSE schemes.
pub trait PartitionFrequencySmoothing<T>: SymmetricEncryption<T>
where
    T: AsBytes + Debug,
{
    /// Initialize all the parameters.
    fn set_params(&mut self, lambda: f64, scale: f64, mle_upper_bound: f64);

    /// Given a vector of `T` and a function closure as the partitioning function, this function constructs the partitioned vectors
    /// containing tuples `(T, usize)` (T and its count).
    fn partition(
        &mut self,
        input: &[T],
        partition_func: &dyn Fn(f64, usize) -> f64,
    );

    /// Transform each partition by duplicating and smoothing each message.
    fn transform(&mut self);

    /// Smoothes the partitions and outputs the ciphertext set.
    fn smooth(&mut self) -> Vec<Vec<u8>>;
}

/// A function used in the partition phase. It takes the form `f(x) = \lambda e^{-\lambda x}`.
pub fn exponential(param: f64, x: usize) -> f64 {
    param * E.powf(-param * x as f64)
}
