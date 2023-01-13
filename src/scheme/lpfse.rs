//! This module implements the frequency smoothing encryption scheme proposed by Lachrite and Paterson.
//!
//! Basically, there are two encoding strategies: the Interval-Based Homophonic Encoding and the Banded
//! Homophonic Encoding, and we implement both of them.

use std::{
    collections::HashMap, f64::consts::PI, fmt::Debug, hash::Hash,
    marker::PhantomData, ops::Range,
};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine};
use rand::{distributions::Uniform, prelude::Distribution};
use rand_core::OsRng;

use crate::{
    db::{Connector, Data},
    fse::{AsBytes, BaseCrypto, HistType},
    util::{build_histogram, build_histogram_vec, compute_cdf, SizeAllocateed},
};

/// A context that represents the frequency-smoothing encryption scheme proposed by Lachrite and Paterson.
///
/// Note that in order to use FSE for plaintext in any type `T`, you must ensure that `T` has the `Hash` and `AsBytes` trait bounds.
/// They are required because `Hash` is needed in the local table, and `AsBytes` is used when performing the cryptographic
/// operations like encryption and pseudorandom string generation.
#[derive(Debug)]
pub struct ContextLPFSE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    /// The advantage of an optimal distinguisher that utilizes the K-S test.
    advantage: f64,
    /// A random key.
    key: Vec<u8>,
    /// The encoder for homophones.
    encoder: Box<dyn HomophoneEncoder<T>>,
    /// The connector to the database.
    conn: Option<Connector<Data>>,
}

/// A trait that defines a generic bahavior of encoders.
pub trait HomophoneEncoder<T>: Debug + SizeAllocateed
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    /// Initialize the encoder.
    fn initialize(&mut self, _messages: &[T], _advantage: f64);

    /// Encode the message and returns one of the homophones from its homophone set.
    fn encode(&self, message: &T) -> Option<Vec<u8>>;

    /// Decode the message. Note we do not return `T` directly.
    fn decode(&self, message: &[u8]) -> Option<Vec<u8>>;
}

/// The encoder for IHBE.
#[derive(Debug, Clone)]
pub struct EncoderIHBE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    /// Stores the interval for each message. Not used after initialization.
    local_table: HashMap<T, Range<u64>>,
}

/// The encoder for BHE.
#[derive(Debug, Clone)]
pub struct EncoderBHE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    /// The length of the band.
    length: usize,
    /// The width of the band.
    width: f64,
    /// The temporary frequency table.
    histogram: HashMap<T, usize>,
    /// A dummy data that consumes `T`.
    _marker: PhantomData<T>,
}

impl<T> EncoderIHBE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    pub fn new() -> Self {
        Self {
            local_table: HashMap::new(),
        }
    }

    /// This function applies Variant 2 on IHBE strategy which modifies how intervals (homophone sets) are allocated
    /// in such a way thatsmaller encoding bitlengths are possible. This is because some distributions can yield
    /// prohibitively large values of r_{min-1} if f_{D}(m_{1})is relatively tiny.
    ///
    /// TODO: Check it.
    fn adjust_distribution(
        &mut self,
        histogram: &mut Vec<HistType<T>>,
        message_num: usize,
        r: f64,
    ) {
        let mut is_big_enough = false;
        let mut scale_factor = 1f64;
        let pow2_r = 1.0 / 2f64.powf(r);
        let pow2_rplus1 = 1.0 / 2f64.powf(r + 1.0);

        for i in 0..histogram.len() {
            let cur_frequency = histogram[i].1 as f64 / message_num as f64;

            if i == 1 {
                if cur_frequency < pow2_rplus1 {
                    // Force the frequency of this message to be aligned to `threshold`.
                    histogram[i].1 =
                        (pow2_rplus1 * message_num as f64).ceil() as usize;

                    scale_factor = (1.0 - cur_frequency) / (1.0 - pow2_rplus1);
                }
            } else if is_big_enough {
                histogram[i].1 =
                    ((histogram[i].1 as f64) / scale_factor).ceil() as usize;
            } else if cur_frequency >= pow2_r * scale_factor {
                is_big_enough = true;
                histogram[i].1 =
                    ((histogram[i].1 as f64) / scale_factor).ceil() as usize;
            } else {
                let cdf_prev = compute_cdf(i, histogram, message_num);
                histogram[i].1 =
                    ((histogram[i].1 as f64) * pow2_r).ceil() as usize;
                let cdf_cur = compute_cdf(i, histogram, message_num);

                scale_factor = (1.0 - cdf_prev) / (1.0 - cdf_cur);
            }
        }
    }
}

impl<T> EncoderBHE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    pub fn new() -> Self {
        Self {
            length: 0,
            width: 0f64,
            histogram: HashMap::new(),
            _marker: PhantomData,
        }
    }

    pub fn get_histogram(&self) -> &HashMap<T, usize> {
        &self.histogram
    }
}

impl<T> Default for EncoderIHBE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Default for EncoderBHE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SizeAllocateed for EncoderBHE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    fn size_allocated(&self) -> usize {
        self.histogram
            .iter()
            .map(|(k, v)| k.size_allocated() + (*v).size_allocated())
            .sum::<usize>()
    }
}

impl<T> SizeAllocateed for EncoderIHBE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    /// No extra space allocated.
    fn size_allocated(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}

impl<T> HomophoneEncoder<T> for EncoderIHBE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    fn initialize(&mut self, messages: &[T], advantage: f64) {
        if messages.is_empty() {
            return;
        }

        self.local_table.clear();
        // Construct a histogram from messages.
        let histogram = build_histogram(messages);
        let mut histogram_vec = build_histogram_vec(&histogram);
        // Also, compute the cumulative frequency for each message.
        let mut sum = 0f64;
        let n = messages.len();

        // f_{D}(m_1).
        let most_frequent = histogram_vec.first().unwrap().1 as f64 / n as f64;
        let log_inner = f64::sqrt(n as f64)
            / (2.0 * f64::sqrt(2.0 * PI) * advantage * most_frequent);
        let r = log_inner.log2().ceil();
        let pow2_r = 2f64.powf(r);

        // Re-adjust the distribution.
        self.adjust_distribution(&mut histogram_vec, messages.len(), r);

        let mut cumulative_frequency = vec![0f64];
        for item in histogram_vec.iter() {
            sum += item.1 as f64 / n as f64;
            cumulative_frequency.push(sum);
        }

        // Construct the local table.
        for item in histogram_vec.iter().enumerate() {
            let lhs = (pow2_r * cumulative_frequency.get(item.0).unwrap())
                .round() as u64;
            let rhs = (pow2_r * cumulative_frequency.get(item.0 + 1).unwrap())
                .round() as u64;
            let range = lhs..rhs;
            self.local_table
                .insert(histogram_vec.get(item.0).unwrap().0.clone(), range);
        }
    }

    fn encode(&self, message: &T) -> Option<Vec<u8>> {
        match self.local_table.get(message) {
            Some(interval) => {
                let homophone = Uniform::new(interval.start, interval.end)
                    .sample(&mut OsRng);

                // Variant 1: Append the homophone to the message.
                let mut encoded_message = message.as_bytes().to_vec();
                encoded_message.extend_from_slice(b"|");
                encoded_message.extend_from_slice(&homophone.to_le_bytes());
                Some(encoded_message)
            }
            None => None,
        }
    }

    fn decode(&self, message: &[u8]) -> Option<Vec<u8>> {
        // Simply strip the homophone from message.
        Some(
            message[..message.len() - std::mem::size_of::<usize>() - 1]
                .to_vec(),
        )
    }
}

impl<T> HomophoneEncoder<T> for EncoderBHE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    fn initialize(&mut self, messages: &[T], advantage: f64) {
        if messages.is_empty() {
            return;
        }

        // Get the histogram of the messages.
        self.histogram = build_histogram(messages);
        let most_frequent = self
            .histogram
            .iter()
            .max_by(|lhs, rhs| lhs.1.cmp(rhs.1))
            .map(|(_, v)| *v)
            .unwrap();

        let n = messages.len() as f64;
        let log2 =
            f64::log2(n / ((2.0 * advantage).powf(2.0) * PI)).ceil() as usize;
        self.length = match log2.checked_sub(1) {
            Some(v) => v,
            None => {
                println!("[-] Invalid length: {}", log2);
                return;
            }
        };
        self.width = most_frequent as f64 / (n * 2f64.powf(self.length as f64));
    }

    fn encode(&self, message: &T) -> Option<Vec<u8>> {
        match self.histogram.get(message) {
            Some(&frequency) => {
                // Compute message m’s frequency band.
                let band = (frequency as f64 / self.width).ceil() as u64;
                let homophone = Uniform::new(0, band).sample(&mut OsRng);

                // Construct m as m || t.
                let mut encoded_message = Vec::new();
                encoded_message.extend_from_slice(message.as_bytes());
                encoded_message.extend_from_slice(b"|");
                encoded_message.extend_from_slice(&homophone.to_le_bytes());
                Some(encoded_message)
            }
            None => None,
        }
    }

    fn decode(&self, message: &[u8]) -> Option<Vec<u8>> {
        // Simply truncate the last l-bits.
        Some(message[..message.len() - std::mem::size_of::<u64>() - 1].to_vec())
    }
}

impl<T> ContextLPFSE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    pub fn new(advantage: f64, encoder: Box<dyn HomophoneEncoder<T>>) -> Self {
        Self {
            advantage,
            key: Vec::new(),
            encoder,
            conn: None,
        }
    }

    pub fn get_encoder(&self) -> &Box<dyn HomophoneEncoder<T>> {
        &self.encoder
    }

    /// Initialize the struct and its connector.
    pub fn initialize(
        &mut self,
        messages: &[T],
        address: &str,
        db_name: &str,
        drop: bool,
    ) {
        // Initialize the encoder.
        self.encoder.initialize(messages, self.advantage);
        // Initialize the connector.
        if let Ok(conn) = Connector::new(address, db_name, drop) {
            self.conn = Some(conn);
        }
    }

    pub fn get_conn(&self) -> &Option<Connector<Data>> {
        &self.conn
    }
}

impl<T> BaseCrypto<T> for ContextLPFSE<T>
where
    T: Hash + AsBytes + Eq + Debug + Clone + SizeAllocateed,
{
    fn key_generate(&mut self) {
        self.key = Aes256Gcm::generate_key(&mut OsRng).to_vec();
    }

    fn encrypt(&self, message: &T) -> Option<Vec<Vec<u8>>> {
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

        let homophone = match self.encoder.encode(message) {
            Some(h) => h,
            None => {
                println!("[-] The requested message does not exist.");
                return None;
            }
        };
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let ciphertext = match aes.encrypt(nonce, homophone.as_slice()) {
            Ok(ciphertext) => ciphertext,
            Err(e) => {
                println!(
                    "[-] Error encrypting the message due to {:?}.",
                    e.to_string()
                );
                return None;
            }
        };
        ciphertexts.push(
            general_purpose::STANDARD_NO_PAD
                .encode(ciphertext)
                .into_bytes(),
        );

        Some(ciphertexts)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        let aes = match Aes256Gcm::new_from_slice(&self.key) {
            Ok(aes) => aes,
            Err(e) => {
                panic!(
                    "[-] Error constructing the AES context due to {:?}.",
                    e.to_string()
                );
            }
        };

        let nonce = Nonce::from_slice(&[0u8; 12]);
        let decoded_plaintext =
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
        let plaintext = match aes.decrypt(nonce, decoded_plaintext.as_slice()) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                println!(
                    "[-] Error decrypting the message due to {:?}.",
                    e.to_string()
                );
                return None;
            }
        };

        self.encoder.decode(&plaintext)
    }
}
