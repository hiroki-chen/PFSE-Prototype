//! This module mainly defines a trait called `FrequencySmoothing` that should be implemented for any struct that tries to act like `FSE`.

pub type HistType<T> = (T, usize);

/// This trait implements the interfaces for any FSE-like schemes.
pub trait FrequencySmoothing<T> {
    /// Initialize all the parameters.
    fn set_params(&mut self, lambda: f64);
    /// Given a security parameter, generate a secret key.
    fn key_generate(&mut self, len: usize);
    /// Given a vector of `T`, return the partitioned vectors containing tuples `(T, usize)` (T and its count).
    fn partition(&self, input: Vec<T>) -> Option<Vec<Vec<HistType<T>>>>;
}
