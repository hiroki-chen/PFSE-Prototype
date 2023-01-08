//! This module implements the partition-based frequency smoothing encryption scheme.

use std::{collections::HashMap, fmt::Debug, hash::Hash};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use rand_core::OsRng;

use crate::{
    fse::{FrequencySmoothing, HistType, PartitionFrequencySmoothing},
    util::build_histogram,
};

#[derive(Debug, Clone)]
pub struct PartitionMeta {
    index: usize,
    cumulative_frequency: f64,
}

#[derive(Clone)]
/// A wrapper for partitions.
pub struct Partition<T>
where
    T: Debug + Clone,
{
    inner: Vec<HistType<T>>,
    meta: PartitionMeta,
}

impl<T> Partition<T>
where
    T: Debug + Clone,
{
    pub fn new(inner: Vec<HistType<T>>, meta: PartitionMeta) -> Self {
        Self { inner, meta }
    }
}

impl<T> Debug for Partition<T>
where
    T: Debug + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Partition #{:0>4}: {{ messages: {:?}, culumative_frequency: {} }}",
            self.meta.index, self.inner, self.meta.cumulative_frequency
        )
    }
}

/// A context that represents an partition-based FSE scheme instance. This struct mainly implements the [`PartitionFrequencySmoothing`] trait.
///
/// Note that in order to use FSE for plaintext in any type `T`, you must ensure that `T` has the `Hash` and `ToString` trait bounds.
/// They are required because `Hash` is needed in the local table, and `ToString` is used when performing the cryptographic
/// operations like encryption and pseudorandom string generation.
///
/// # Example
/// ```rust
/// use fse::{ContextPFSE, fse::FrequencySmoothing};
///
/// let mut ctx = ContextPFSE<i32>::default();
/// ctx.set_params(...);
/// ctx.key_generate();
///
/// println!("[+] FSE is ready? {}", ctx.ready());
/// ```
#[derive(Debug, Clone)]
pub struct ContextPFSE<T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    /// Is this context fully initialized?
    is_ready: bool,
    /// A random key used in pseudorandom function.
    key: Vec<u8>,
    /// A table that stores the size of the ciphertext set for a given plaintext message `T`.
    local_table: HashMap<T, usize>,
    /// The parameter for partition.
    p_partition: f64,
    /// The scaling factor k_0.
    p_scale: f64,
    /// The parameter for transformation. A.k.a., k' and k''.
    p_transform: (f64, f64),
    /// The upper-bound of the advantage a MLE attacker.
    p_mle_upper_bound: f64,
    /// The number of messages.
    message_num: usize,
    /// Partitions.
    partitions: Vec<Partition<T>>,
}

impl<T> ContextPFSE<T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    pub fn ready(&self) -> bool {
        self.is_ready
    }

    pub fn get_local_table(&self) -> &HashMap<T, usize> {
        &self.local_table
    }

    pub fn get_param_partition(&self) -> f64 {
        self.p_partition
    }

    pub fn get_param_transform(&self) -> (f64, f64) {
        self.p_transform
    }

    pub fn get_partition_num(&self) -> usize {
        self.partitions.len()
    }

    pub fn get_message_num(&self) -> usize {
        self.message_num
    }

    pub fn get_partitions(&self) -> &Vec<Partition<T>> {
        &self.partitions
    }

    /// A private method used to check if two factors `k'` and `k''` satisfy the mathematical constraint.
    ///
    /// If factors are chosen such that they do not conform to the constraint, the program need to re-sample a new pair
    /// to ensure that the upper-bound of the MLE advantage can always be satisfied, or you can simply abort the execution.
    fn check_ki(&self, ki: f64) -> bool {
        let threadhold = (self.p_mle_upper_bound * self.message_num as f64)
            / (self.p_partition * self.p_scale * self.get_partition_num() as f64);
        println!("{}", threadhold);

        ki <= threadhold
    }
}

impl<T> Default for ContextPFSE<T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    fn default() -> Self {
        Self {
            is_ready: false,
            key: Vec::new(),
            local_table: HashMap::new(),
            p_partition: 0f64,
            p_transform: (0f64, 0f64),
            p_mle_upper_bound: 0f64,
            p_scale: 0f64,
            message_num: 0usize,
            partitions: Vec::new(),
        }
    }
}

impl<T> FrequencySmoothing<T> for ContextPFSE<T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    fn key_generate(&mut self) {
        self.key = Aes256Gcm::generate_key(&mut OsRng).to_vec();
    }

    fn encrypt(&mut self, message: &T) -> Vec<Vec<u8>> {
        let mut ciphertexts = Vec::new();
        let aes = match Aes256Gcm::new_from_slice(&self.key) {
            Ok(aes) => aes,
            Err(e) => {
                panic!(
                    "[-] Error constructing the AES context due to {:?}.",
                    e.to_string()
                );
            }
        };

        // For statical distribution: check if the local table contains this message; if not, we do nothing.
        if self.local_table.contains_key(message) {
            let item = self.local_table.get(message).unwrap();

            for i in 1..=*item {
                let mut message_byte = Vec::new();
                message_byte.extend_from_slice(item.to_string().as_bytes());
                message_byte.extend_from_slice(&i.to_le_bytes());
                let nonce = Nonce::from_slice(b"0");

                // Encrypt the message.
                // ciphertext = AES.encrypt(key, message || idx, 0);
                let ciphertext = match aes.encrypt(nonce, message_byte.as_slice()) {
                    Ok(ciphertext) => ciphertext,
                    Err(e) => {
                        panic!(
                            "[-] Error encrypting the message due to {:?}.",
                            e.to_string()
                        );
                    }
                };
                ciphertexts.push(ciphertext);
            }
        } else {
            println!("[-] The requested message does not exists, skip.");
        }

        ciphertexts
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let aes = match Aes256Gcm::new_from_slice(&self.key) {
            Ok(aes) => aes,
            Err(e) => {
                panic!(
                    "[-] Error constructing the AES context due to {:?}.",
                    e.to_string()
                );
            }
        };
        let nonce = Nonce::from_slice(b"0");
        let mut plaintext = match aes.decrypt(nonce, ciphertext) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                panic!(
                    "[-] Error decrypting the message due to {:?}.",
                    e.to_string()
                );
            }
        };
        plaintext.truncate(plaintext.len() - std::mem::size_of::<usize>());

        plaintext
    }
}

impl<T> PartitionFrequencySmoothing<T> for ContextPFSE<T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    fn set_params(&mut self, lambda: f64, scale: f64, mle_upper_bound: f64) {
        self.p_partition = lambda;
        self.p_scale = scale;
        self.p_mle_upper_bound = mle_upper_bound;
        self.is_ready = true;
    }

    fn partition(&mut self, input: &Vec<T>, partition_func: &dyn Fn(f64, usize) -> f64) {
        if !self.ready() {
            panic!("[-] Context not ready.");
        }

        self.message_num = input.len();
        let mut histogram_vec = build_histogram(input);
        // Partition this according to the function f(x).
        let mut i = 0usize;
        // The group number.
        let mut group = 1usize;
        while i < histogram_vec.len() {
            // Temporary right size of the interval [i, j].
            let mut j = i;
            // Cumulative sum, i.e. \sum_{k \in [i, j]} f_{D}(m_{k}) = sum.
            let mut sum = 0f64;
            // Calculate \lambda * e^{-\lambda group}.
            let value = partition_func(self.p_partition, group);

            while j < histogram_vec.len() && sum < value {
                sum += histogram_vec[j].1 as f64 / self.message_num as f64;

                j += 1;
            }

            // Deal with a special case: \sum_{k \in [i, j]} \in (f(group), f(group + 1));
            if sum > value {
                let diff = sum - value;
                // Split j-th message.
                let message_first_part = (
                    histogram_vec[j - 1].0.clone(),
                    (histogram_vec[j - 1].1 as f64 * (1f64 - diff)).ceil() as usize,
                );
                let message_second_part = (
                    histogram_vec[j - 1].0.clone(),
                    (histogram_vec[j - 1].1 as f64 * diff).floor() as usize,
                );

                histogram_vec[j - 1] = message_first_part;
                self.partitions.push(Partition::new(
                    histogram_vec[i..j].to_vec().clone(),
                    PartitionMeta {
                        index: group,
                        cumulative_frequency: value,
                    },
                ));

                if message_second_part.1 != 0 {
                    // Insert the second part into the vector again (descending order).
                    let pos = histogram_vec[j..]
                        .binary_search_by(|(_, freq)| message_second_part.1.cmp(freq))
                        .unwrap_or_else(|e| e);
                    histogram_vec.insert(pos + j, message_second_part);
                }
            } else {
                self.partitions.push(Partition::new(
                    histogram_vec[i..j].to_vec().clone(),
                    PartitionMeta {
                        index: group,
                        cumulative_frequency: value,
                    },
                ));
            }

            group += 1;
            i = j;
        }

        println!("{:#?}\n{:?}", self.partitions, histogram_vec);
    }

    fn transform(&mut self) {
        for partition in self.partitions.iter() {
            // FIXME: How to sample them?
            let k_prime_one = 0.25;
            let k_prime_second = 5.0;

            if !self.check_ki(k_prime_one / k_prime_second) {
                panic!("[-] This pair of parameters is invalid.");
            }

            for message in partition.inner.iter() {
                let set_size = (k_prime_one * message.1 as f64).ceil();
                let pdf =
                    1f64 / k_prime_second * partition.meta.cumulative_frequency * self.p_scale;

                println!("set size = {}, pdf = {}", set_size, pdf);
            }
        }
    }
}
