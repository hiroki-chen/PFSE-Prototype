//! This module implements the partition-based frequency smoothing encryption scheme.

use std::{collections::HashMap, f64::consts::E, fmt::Debug, hash::Hash};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine};
use log::{debug, warn};
use rand_core::OsRng;

use crate::{
    db::{Connector, Data},
    fse::{
        AsBytes, BaseCrypto, Conn, FreqType, FromBytes, HistType,
        PartitionFrequencySmoothing, Random, ValueType, DEFAULT_RANDOM_LEN,
    },
    util::{build_histogram, build_histogram_vec, SizeAllocated},
};

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
    pub inner: Vec<HistType<T>>,
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

    /// Find the maximum frequency within the partition.
    pub fn max_freq(&self) -> f64 {
        self.inner.first().unwrap().1 as f64 / self.meta.message_num as f64
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
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + Random + SizeAllocated,
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
    /// The upper-bound of the advantage of the inference attacker. For example, `p_advantage` = 0.1, then the advantage should be no larger than 0.1 * baseline.
    p_advantage: f64,
    /// The partition function pointer.
    partition_func: Option<fn(f64, usize) -> f64>,
    /// The number of messages.
    message_num: usize,
    /// Partitions.
    partitions: Vec<Partition<T>>,
    /// Connector to the database.
    conn: Option<Connector<Data>>,
}

impl<T> ContextPFSE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + Random + SizeAllocated,
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

    /// Returns all unique ciphertexts.
    /// Note this interface with `repeat = false` should only be invoked by `search => encrypt`.
    fn encrypt_impl(&self, message: &T, repeat: bool) -> Option<Vec<Vec<u8>>> {
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
            debug!("{index}, {size}, {cnt}");
            for j in 0..size {
                let nonce = Nonce::from_slice(&[0u8; 12usize]);
                let mut message_vec = message.as_bytes().to_vec();
                message_vec.extend_from_slice(b"|");
                message_vec.extend_from_slice(&index.to_le_bytes());
                message_vec.extend_from_slice(b"|");
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

                if repeat {
                    let mut ciphertext_vec = vec![encoded_ciphertext; cnt];
                    ciphertexts.append(&mut ciphertext_vec);
                } else {
                    ciphertexts.push(encoded_ciphertext);
                }
            }
        }

        Some(ciphertexts)
    }
}

impl<T> Conn for ContextPFSE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + Random + SizeAllocated,
{
    fn get_conn(&self) -> &Connector<Data> {
        self.conn.as_ref().unwrap()
    }
}

impl<T> Default for ContextPFSE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + Random + SizeAllocated,
{
    fn default() -> Self {
        Self {
            is_ready: false,
            key: Vec::new(),
            local_table: HashMap::new(),
            p_partition: 0f64,
            p_transform: (0f64, 0f64),
            p_advantage: 0f64,
            p_scale: 0f64,
            partition_func: None,
            message_num: 0usize,
            partitions: Vec::new(),
            conn: None,
        }
    }
}

impl<T> SizeAllocated for ContextPFSE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + Random + SizeAllocated,
{
    fn size_allocated(&self) -> usize {
        self.local_table.size_allocated()
    }
}

impl<T> BaseCrypto<T> for ContextPFSE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + Random + SizeAllocated,
{
    fn key_generate(&mut self) {
        self.key = Aes256Gcm::generate_key(&mut OsRng).to_vec();
    }

    fn encrypt(&mut self, message: &T) -> Option<Vec<Vec<u8>>> {
        self.encrypt_impl(message, false)
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
        plaintext
            .truncate(plaintext.len() - std::mem::size_of::<usize>() * 2 - 2);

        Some(plaintext)
    }
}

impl<T> PartitionFrequencySmoothing<T> for ContextPFSE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + Random + SizeAllocated,
{
    fn set_params(&mut self, params: &[f64]) {
        if params.len() != 3 {
            log::error!("The number of the parameter is incorrect.");
            return;
        }

        self.p_partition = params[0];
        self.p_scale = params[1];
        self.p_advantage = params[2];
        self.is_ready = true;
    }

    fn partition(
        &mut self,
        input: &[T],
        partition_func: fn(f64, usize) -> f64,
    ) {
        // Set the partition function.
        self.partition_func = Some(partition_func);
        if !self.ready() {
            panic!("[-] Context not ready.");
        }

        self.message_num = input.len();
        let mut histogram_vec = {
            let histogram = build_histogram(input);
            build_histogram_vec(&histogram)
        };
        debug!("Histogram: {:?}", histogram_vec);
        // Partition this according to the function f(x).
        let mut i = 0usize;
        // The group number.
        let mut group = 1usize;
        while i < histogram_vec.len() {
            // Calculate \lambda * e^{-\lambda group} * k_{0}.
            let value = partition_func(self.p_partition, group) * self.p_scale;
            if value * self.message_num as f64 <= 1.0 {
                self.partitions.push(Partition::new(
                    histogram_vec[i..].to_vec(),
                    group,
                    histogram_vec[i..]
                        .iter()
                        .map(|e| e.1 as f64 / self.message_num as f64)
                        .sum(),
                ));
                break;
            }

            // Temporary right size of the interval [i, j].
            let mut j = i;
            // Cumulative sum, i.e. \sum_{k \in [i, j]} f_{D}(m_{k}) = sum.
            let mut sum = 0f64;

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
                    (histogram_vec[j - 1].1 as f64 * (1f64 - diff)).ceil()
                        as usize,
                );
                let message_second_part = (
                    histogram_vec[j - 1].0.clone(),
                    (histogram_vec[j - 1].1 as f64 * diff).floor() as usize,
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
    }

    fn transform(&mut self) {
        // k_i &= \frac{e^{\lambda i}}{\sqrt{nk}} \\
        // n_i &= \frac{\sqrt{nk}|G_i|}{(\Delta + c) \cdot e^{\lambda i} }
        let k = self.partitions.len() as f64;
        let n = self.message_num as f64;

        // Compute `p_advantage`.
        let baseline =
            self.partitions.iter().map(|e| e.max_freq()).sum::<f64>();
        self.p_advantage *= baseline;
        log::info!(
            "The baseline is {}, and the advantage is {}.",
            baseline,
            self.p_advantage
        );

        for (index, partition) in self.partitions.iter_mut().enumerate() {
            let f_i = partition
                .inner
                .iter()
                .map(|e| (e.1 as f64 / n).powf(2.0))
                .sum::<f64>();
            let cur_func =
                (self.partition_func.unwrap())(self.p_partition, index + 1);
            let k_prime_one = cur_func / k;
            let k_prime_one_reciprocal = 1.0 / (k_prime_one);
            let n_i = ((n * f_i) / self.p_advantage).ceil() as usize;

            let mut sum = 0;

            for (message, cnt) in partition.inner.iter() {
                let size = (k_prime_one * *cnt as f64).ceil() as usize;
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
                None => {
                    warn!(
                        "Partition #{:<4}: attemping to subtract {} by {}.",
                        index, n_i, sum
                    );
                    0
                }
            };

            log::debug!(
                "# {}... |G_i| = {}, sum = {}, ni = {}, k_one = {}, f_i = {}.",
                index,
                partition.inner.len(),
                sum,
                n_i,
                k_prime_one,
                f_i,
            );

            for _ in sum..delta {
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

        let mut visited = HashMap::new();
        // Temporarily clone this thing to prevent multiple borrows to `self`.
        for partition in self.partitions.clone().into_iter() {
            for (message, cnt) in partition.inner.iter() {
                if visited.get(message).is_none() {
                    if let Some(mut c) = self.encrypt(message) {
                        ciphertexts.append(&mut c);
                    } else {
                        let mut dummies =
                            vec![message.clone().as_bytes().to_vec(); *cnt];
                        ciphertexts.append(&mut dummies);
                    }

                    visited.insert(message.clone(), true);
                }
            }
        }

        ciphertexts
    }
}
