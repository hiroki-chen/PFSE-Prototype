//! This module mainly defines a trait called `FrequencySmoothing` that should be implemented for any struct that tries to act like `FSE`.

use std::f64::consts::E;

pub type HistType<T> = (T, usize);

/// This trait implements the interfaces for any FSE-like schemes.
pub trait FrequencySmoothing<T> {
    /// Initialize all the parameters.
    fn set_params(&mut self, lambda: f64, scale: f64, mle_upper_bound: f64);
    /// Given a security parameter, generate a secret key.
    fn key_generate(&mut self, len: usize);
    /// Given a vector of `T` and a function closure as the partitioning function, this function returns the partitioned vectors
    /// containing tuples `(T, usize)` (T and its count).
    fn partition(
        &mut self,
        input: Vec<T>,
        f: &dyn Fn(f64, usize) -> f64,
    ) -> Option<Vec<Vec<HistType<T>>>>;
}

/// A function used in the partition phase. It takes the form `f(x) = \lambda e^{-\lambda x}`.
pub fn exponential(param: f64, x: usize) -> f64 {
    param * E.powf(-param * x as f64)
}
