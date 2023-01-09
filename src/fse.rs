//! This module mainly defines a trait called `FrequencySmoothing` that should be implemented for any struct that tries to act like `FSE`.

use std::f64::consts::E;

pub type HistType<T> = (T, usize);
pub type FreqType<T> = (T, f64);

/// This trait implements the interfaces for any FSE-like schemes.

pub trait FrequencySmoothing<T> {
    /// Given a security parameter, generate a secret key.
    fn key_generate(&mut self);

    /// Encrypt the message and return the ciphertext vector. Return `None` if error occurrs.
    fn encrypt(&mut self, message: &T) -> Option<Vec<Vec<u8>>>;

    /// Decrypt the ciphertext and return the plaintext. Return `None` if error occurrs.
    fn decrypt(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>>;
}

/// This trait is derived from [`FrequencySmoothing`] for partition-based FSE schemes.
pub trait PartitionFrequencySmoothing<T>: FrequencySmoothing<T> {
    /// Initialize all the parameters.
    fn set_params(&mut self, lambda: f64, scale: f64, mle_upper_bound: f64);

    /// Given a vector of `T` and a function closure as the partitioning function, this function constructs the partitioned vectors
    /// containing tuples `(T, usize)` (T and its count).
    fn partition(&mut self, input: &[T], partition_func: &dyn Fn(f64, usize) -> f64);

    /// Transform each partition by duplicating and smoothing each message.
    fn transform(&mut self);
}

/// A function used in the partition phase. It takes the form `f(x) = \lambda e^{-\lambda x}`.
pub fn exponential(param: f64, x: usize) -> f64 {
    param * E.powf(-param * x as f64)
}
