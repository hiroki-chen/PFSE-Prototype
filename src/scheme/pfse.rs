//! This module implements the partition-based frequency smoothing encryption scheme.

use std::{collections::HashMap, f64::consts::E, fmt::Debug, hash::Hash};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine};
use rand_core::OsRng;

use crate::{
    db::{Connector, Data},
    fse::{
        AsBytes, BaseCrypto, Conn, FreqType, FromBytes, HistType,
        PartitionFrequencySmoothing, Random, ValueType, DEFAULT_RANDOM_LEN,
    },
    util::{build_histogram, build_histogram_vec, SizeAllocateed},
};

/// This struct defines the parameter pair that can be used to transform each partition `G_i`.
///
/// Formally speaking, K is such that
/// ```tex
///   K = \frac{k''_i}{k'_i} \leq threshold.
/// ```
#[derive(Clone)]
pub struct K {
    k_one: f64,
    k_second: f64,
}

impl K {
    pub fn new(k_one: f64, k_second: f64) -> Self {
        Self { k_one, k_second }
    }

    pub fn get(&self) -> f64 {
        self.k_one / self.k_second
    }
}

impl Debug for K {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let res = self.k_one / self.k_second;
        write!(f, "{} / {} = {}", self.k_one, self.k_second, res)
    }
}

impl PartialEq for K {
    fn eq(&self, other: &Self) -> bool {
        let lhs = self.k_one / self.k_second;
        let rhs = other.k_one / other.k_second;
        (lhs - rhs).abs() <= 1.0e-6
    }
}

impl Eq for K {}

#[derive(Debug, Clone)]
pub struct PartitionMeta {
    index: usize,
    cumulative_frequency: f64,
    /// The number of messages within this partition.
    message_num: usize,
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
    pub fn new(
        inner: Vec<HistType<T>>,
        index: usize,
        cumulative_frequency: f64,
    ) -> Self {
        let meta = PartitionMeta {
            index,
            cumulative_frequency,
            message_num: inner.iter().map(|elem| elem.1).sum(),
        };
        Self { inner, meta }
    }

    /// Convert a histogram `Vec<HistType<T>>` into a frequency table `Vec<FreqType<T>>`. See [`FreqType`] and [`HistType`].
    pub fn build_frequency_table(&self) -> Vec<FreqType<T>> {
        self.inner
            .iter()
            .map(|elem| {
                (elem.0.clone(), elem.1 as f64 / self.meta.message_num as f64)
            })
            .collect()
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
/// Note that in order to use FSE for plaintext in any type `T`, you must ensure that `T` has the `Hash` and `AsBytes` trait bounds.
/// They are required because `Hash` is needed in the local table, and `AsBytes` is used when performing the cryptographic
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
    T: Hash
        + AsBytes
        + FromBytes
        + Eq
        + Debug
        + Clone
        + Random
        + SizeAllocateed,
{
    /// Is this context fully initialized?
    is_ready: bool,
    /// A random key used in pseudorandom function.
    key: Vec<u8>,
    /// A table that stores the size of the ciphertext set for different partitions,
    /// given a plaintext message `T`.
    local_table: HashMap<T, Vec<ValueType>>,
    /// The parameter for partition.
    p_partition: f64,
    /// The scaling factor k_0.
    p_scale: f64,
    /// The parameter for transformation. A.k.a., k' and k''.
    p_transform: (f64, f64),
    /// The upper-bound of the advantage a MLE attacker.
    p_mle_upper_bound: f64,
    /// The threshold for K_{i} = \frac{k'_i}{k''_i}.
    p_threshold: f64,
    /// The number of messages.
    message_num: usize,
    /// Partitions.
    partitions: Vec<Partition<T>>,
    /// Connector to the database.
    conn: Option<Connector<Data>>,
}

impl<T> ContextPFSE<T>
where
    T: Hash
        + AsBytes
        + FromBytes
        + Eq
        + Debug
        + Clone
        + Random
        + SizeAllocateed,
{
    pub fn ready(&self) -> bool {
        self.is_ready
    }

    pub fn get_local_table(&self) -> &HashMap<T, Vec<ValueType>> {
        &self.local_table
    }

    pub fn get_param_partition(&self) -> f64 {
        self.p_partition
    }

    pub fn get_param_transform(&self) -> (f64, f64) {
        self.p_transform
    }

    pub fn get_param_threshold(&self) -> f64 {
        self.p_threshold
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

    /// Initialize the database.
    pub fn initialize_conn(
        &mut self,
        address: &str,
        db_name: &str,
        drop: bool,
    ) {
        if let Ok(conn) = Connector::new(address, db_name, drop) {
            self.conn = Some(conn);
        }
    }
}

impl<T> Conn for ContextPFSE<T>
where
    T: Hash
        + AsBytes
        + FromBytes
        + Eq
        + Debug
        + Clone
        + Random
        + SizeAllocateed,
{
    fn get_conn(&self) -> &Connector<Data> {
        self.conn.as_ref().unwrap()
    }
}

impl<T> Default for ContextPFSE<T>
where
    T: Hash
        + AsBytes
        + FromBytes
        + Eq
        + Debug
        + Clone
        + Random
        + SizeAllocateed,
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
            p_threshold: 0f64,
            message_num: 0usize,
            partitions: Vec::new(),
            conn: None,
        }
    }
}

impl<T> BaseCrypto<T> for ContextPFSE<T>
where
    T: Hash
        + AsBytes
        + FromBytes
        + Eq
        + Debug
        + Clone
        + Random
        + SizeAllocateed,
{
    fn key_generate(&mut self) {
        self.key = Aes256Gcm::generate_key(&mut OsRng).to_vec();
    }

    fn encrypt(&self, message: &T) -> Option<Vec<Vec<u8>>> {
        let value = match self.local_table.get(message) {
            Some(v) => v,
            None => return None,
        };

        let mut ciphertexts = Vec::new();
        let aes = match Aes256Gcm::new_from_slice(&self.key) {
            Ok(aes) => aes,
            Err(e) => {
                println!(
                    "[-] Error constructing the AES context due to {:?}.",
                    e.to_string()
                );
                return None;
            }
        };

        for &(index, size, cnt) in value.iter() {
            for j in 0..size {
                let nonce = Nonce::from_slice(&[0u8; 12usize]);
                let mut message_vec = message.as_bytes().to_vec();
                message_vec.extend_from_slice(&index.to_le_bytes());
                message_vec.extend_from_slice(&j.to_le_bytes());
                let ciphertext =
                    match aes.encrypt(nonce, message_vec.as_slice()) {
                        Ok(v) => v,
                        Err(e) => {
                            println!(
                            "[-] Error when encrypting the message due to {:?}",
                            e
                        );
                            return None;
                        }
                    };
                let encoded_ciphertext = general_purpose::STANDARD_NO_PAD
                    .encode(ciphertext)
                    .into_bytes();
                let mut ciphertext_vec = vec![encoded_ciphertext; cnt];
                ciphertexts.append(&mut ciphertext_vec);
            }
        }

        Some(ciphertexts)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let aes = match Aes256Gcm::new_from_slice(&self.key) {
            Ok(aes) => aes,
            Err(e) => {
                println!(
                    "[-] Error constructing the AES context due to {:?}.",
                    e.to_string()
                );
                return None;
            }
        };
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let decoded_ciphertext =
            match general_purpose::STANDARD_NO_PAD.decode(ciphertext) {
                Ok(v) => v,
                Err(e) => {
                    println!(
                        "[-] Error decoding the base64 string due to {:?}.",
                        e.to_string()
                    );
                    return None;
                }
            };
        let mut plaintext =
            match aes.decrypt(nonce, decoded_ciphertext.as_slice()) {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    println!(
                        "[-] Error decrypting the message due to {:?}.",
                        e.to_string()
                    );
                    return None;
                }
            };
        plaintext.truncate(plaintext.len() - std::mem::size_of::<usize>() * 2);

        Some(plaintext)
    }
}

impl<T> PartitionFrequencySmoothing<T> for ContextPFSE<T>
where
    T: Hash
        + AsBytes
        + FromBytes
        + Eq
        + Debug
        + Clone
        + Random
        + SizeAllocateed,
{
    fn set_params(&mut self, lambda: f64, scale: f64, mle_upper_bound: f64) {
        self.p_partition = lambda;
        self.p_scale = scale;
        self.p_mle_upper_bound = mle_upper_bound;
        self.is_ready = true;
    }

    fn partition(
        &mut self,
        input: &[T],
        partition_func: &dyn Fn(f64, usize) -> f64,
    ) {
        if !self.ready() {
            panic!("[-] Context not ready.");
        }

        self.message_num = input.len();
        let mut histogram_vec = {
            let histogram = build_histogram(input);
            build_histogram_vec(&histogram)
        };
        // Partition this according to the function f(x).
        let mut i = 0usize;
        // The group number.
        let mut group = 1usize;
        while i < histogram_vec.len() {
            // Temporary right size of the interval [i, j].
            let mut j = i;
            // Cumulative sum, i.e. \sum_{k \in [i, j]} f_{D}(m_{k}) = sum.
            let mut sum = 0f64;
            // Calculate \lambda * e^{-\lambda group} * k_{0}.
            let value = partition_func(self.p_partition, group) * self.p_scale;

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
                    (histogram_vec[j - 1].1 as f64 * (1f64 - diff)).round()
                        as usize,
                );
                let message_second_part = (
                    histogram_vec[j - 1].0.clone(),
                    (histogram_vec[j - 1].1 as f64 * diff).round() as usize,
                );

                histogram_vec[j - 1] = message_first_part;
                self.partitions.push(Partition::new(
                    histogram_vec[i..j].to_vec().clone(),
                    group,
                    value,
                ));

                if message_second_part.1 != 0 {
                    // Insert the second part into the vector again (descending order).
                    let pos = histogram_vec[j..]
                        .binary_search_by(|(_, freq)| {
                            message_second_part.1.cmp(freq)
                        })
                        .unwrap_or_else(|e| e);
                    histogram_vec.insert(pos + j, message_second_part);
                }
            } else {
                self.partitions.push(Partition::new(
                    histogram_vec[i..j].to_vec().clone(),
                    group,
                    value,
                ));
            }

            group += 1;
            i = j;
        }

        // Set threshold.
        self.p_threshold = (self.p_mle_upper_bound * self.message_num as f64)
            / (self.p_partition
                * self.p_scale
                * self.get_partition_num() as f64);
    }

    fn transform(&mut self) {
        let k = self.partitions.len();
        for (index, partition) in self.partitions.iter_mut().enumerate() {
            // Calculate \alpha.
            let most_frequent = partition.inner.first().unwrap().1;
            let alpha =
                ((self.p_partition * k as f64 * self.p_scale.powf(2.0))
                    / (self.p_mle_upper_bound
                        * most_frequent as f64
                        * partition.inner.len() as f64))
                    .min(1.0);

            // There are some constraints that should be taken into consideration.
            // 1. n_i &\geq k'_i \cdot \max_{m \in G_{i}} \{ n_{M}(m) \} \cdot |G_{i}|
            // 2. \sum_{i \in [k]} \frac{k'_i}{k''_i} \lambda e^{-\lambda i} &\leq \frac{(\Delta + c) |M|}{k_{0}}

            let k_prime_one = (self.p_partition * (index as f64 + 1.0))
                / (k as f64 * partition.inner.len() as f64);
            let k_prime_second = (self.p_scale
                * E.powf(self.p_partition * (index as f64 + 1.0))
                * self.p_partition
                * (index as f64 + 1.0))
                / (alpha
                    * self.p_mle_upper_bound
                    * self.message_num as f64
                    * partition.inner.len() as f64);
            let k_prime_one_reciprocal = 1.0 / k_prime_one;

            // Add an extra 1 to prevent problems related to precisions.
            let n_i = (k_prime_second
                * self.p_partition
                * E.powf(-self.p_partition * (index as f64 + 1.0))
                * self.p_scale
                * self.message_num as f64)
                .ceil() as usize
                + 1;
            let mut sum = 0;

            for (message, cnt) in partition.inner.iter() {
                let size = (k_prime_one * *cnt as f64).round() as usize;
                let cur = self.local_table.entry(message.clone()).or_default();
                cur.push((
                    index,
                    size,
                    k_prime_one_reciprocal.round() as usize,
                ));
                sum += size;
            }

            let delta = match n_i.checked_sub(sum) {
                Some(d) => d,
                None => panic!(
                    "[-] Internal error: attemping to subtract {} by {}.",
                    n_i, sum
                ),
            };
            for _ in sum + 1..=delta {
                // Insert dummy values.
                let dummy = T::random(DEFAULT_RANDOM_LEN);

                partition
                    .inner
                    .push((dummy, (1.0 / k_prime_one).ceil() as usize));
            }
        }
    }

    fn smooth(&mut self) -> Vec<Vec<u8>> {
        let mut ciphertexts = Vec::new();

        for partition in self.partitions.iter() {
            for (message, cnt) in partition.inner.iter() {
                if let Some(mut c) = self.encrypt(message) {
                    ciphertexts.append(&mut c);
                } else {
                    let mut dummies =
                        vec![message.clone().as_bytes().to_vec(); *cnt];
                    ciphertexts.append(&mut dummies);
                }
            }
        }

        ciphertexts
    }
}
