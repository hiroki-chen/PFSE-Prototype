//! This module defines a context for frequency smoothing encryption scheme.

use std::{collections::HashMap, f64::consts::E, fmt::Debug, hash::Hash};

use rand_core::{OsRng, RngCore};

use crate::fse::{FrequencySmoothing, HistType};

/// A context that represents an FSE scheme instance. This struct mainly implements the [`FrequencySmoothing`] trait.
///
/// Note that in order to use FSE for plaintext in any type `T`, you must ensure that `T` has the `Hash` and `ToString` trait bounds.
/// They are required because `Hash` is needed in the local table, and `ToString` is used when performing the cryptographic
/// operations like encryption and pseudorandom string generation.
///
/// # Example
/// ```rust
/// use fse::{FSEContext, fse::FrequencySmoothing};
///
/// let mut ctx = FSEContext<i32>::default();
/// ctx.set_params(...);
/// ctx.key_generate();
///
/// println!("[+] FSE is ready? {}", ctx.ready());
/// ```
#[derive(Debug, Clone)]
pub struct FSEContext<'a, T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    /// Is this context fully initialized?
    is_ready: bool,
    /// A random key used in pseudorandom function.
    key: Vec<u8>,
    /// A table that stores the size of the ciphertext set for a given plaintext message `T`.
    local_table: HashMap<&'a T, usize>,
    /// The parameter for partition
    p_partition: f64,
}

impl<'a, T> FSEContext<'a, T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    pub fn ready(&self) -> bool {
        self.is_ready
    }

    pub fn get_local_table(&self) -> &HashMap<&'a T, usize> {
        &self.local_table
    }

    pub fn get_param_partition(&self) -> f64 {
        self.p_partition
    }
}

impl<'a, T> Default for FSEContext<'a, T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    fn default() -> Self {
        Self {
            is_ready: false,
            key: Vec::new(),
            local_table: HashMap::new(),
            p_partition: 0f64,
        }
    }
}

impl<'a, T> FrequencySmoothing<T> for FSEContext<'a, T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    fn key_generate(&mut self, len: usize) {
        self.key.clear();
        self.key.reserve(len);
        OsRng.fill_bytes(&mut self.key);
    }

    fn set_params(&mut self, lambda: f64) {
        self.p_partition = lambda;

        self.is_ready = true;
    }

    fn partition(&self, input: Vec<T>) -> Option<Vec<Vec<HistType<T>>>> {
        if !self.ready() {
            println!("[-] Context not ready.");
            return None;
        }

        let message_num = input.len();
        let mut histogram = HashMap::<T, usize>::new();
        // Construct the histogram for `input`.
        for i in input.into_iter() {
            let entry = histogram.entry(i).or_insert(0);
            *entry = match entry.checked_add(1) {
                Some(val) => val,
                None => return None,
            };
        }

        // Partition this according to the function f(x) = \lambda e^{-\lambda x}.
        // First, convert histogram into vector that is ordered by frequency.
        let mut histogram_vec = Vec::new();
        histogram
            .into_iter()
            .for_each(|(key, frequency)| histogram_vec.push((key, frequency)));
        // Second, sort the vector in descending order.
        histogram_vec.sort_by(|lhs, rhs| rhs.1.cmp(&lhs.1));

        // Finally, partition the histogram_vec.
        let mut i = 0usize;
        // The group number.
        let mut group = 1usize;
        let mut partitions = Vec::new();
        while i < histogram_vec.len() {
            let mut j = i;

            // Cumulative sum, i.e. \sum_{k \in [i, j]} f_{D}(m_{k}) = sum.
            let mut sum = 0f64;
            // Calculate \lambda * e^{-\lambda group}.
            let value = self.p_partition * E.powf(-self.p_partition * group as f64);
            println!("cur value is {}", value);
            // TODO: If j > len but sum < value, we need to do some padding.
            // TODO: What if a message cannot be partitioned into this group?
            while j < histogram_vec.len() && sum <= value {
                sum += histogram_vec[j].1 as f64 / message_num as f64;
                j += 1;
            }

            partitions.push(histogram_vec[i..j].to_vec().clone());

            group += 1;
            i = j;
        }

        println!("{:?}", partitions);

        Some(partitions)
    }
}
