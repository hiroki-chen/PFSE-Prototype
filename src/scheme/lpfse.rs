//! This module implements the frequency smoothing encryption scheme proposed by Lachrite and Paterson.
//!
//! Basically, there are two encoding strategies: the Interval-Based Homophonic Encoding and the Banded
//! Homophonic Encoding, and we implement both of them.

use std::collections::HashMap;
use std::f64::consts::PI;
use std::fmt::Debug;
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::Range;

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use rand_core::OsRng;

use crate::{fse::FrequencySmoothing, util::build_histogram};

/// A context that represents the frequency-smoothing encryption scheme proposed by Lachrite and Paterson.
///
/// Note that in order to use FSE for plaintext in any type `T`, you must ensure that `T` has the `Hash` and `ToString` trait bounds.
/// They are required because `Hash` is needed in the local table, and `ToString` is used when performing the cryptographic
/// operations like encryption and pseudorandom string generation.
#[derive(Debug)]
pub struct ContextLPFSE<T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    /// The advantage of an optimal distinguisher that utilizes the K-S test.
    advantage: f64,
    /// A random key.
    key: Vec<u8>,
    /// The encoder for homophones.
    encoder: Box<dyn HomophoneEncoder<T>>,
    /// A phantom marker.
    _marker: PhantomData<T>,
}

/// A trait that defines a generic bahavior of encoders.
pub trait HomophoneEncoder<T>: Debug
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    /// Initialize the encoder.
    fn initialize(&mut self, _messages: &Vec<T>, _advantage: f64) {
        return;
    }

    /// Encode the message and returns one of the homophones from its homophone set.
    fn encode(&mut self, message: &T) -> Vec<u8>;

    /// Decode the message. Note we do not return `T` directly.
    fn decode(&mut self, message: &[u8]) -> Vec<u8>;
}

/// The encoder for IHBE.
#[derive(Debug, Clone)]
pub struct EncoderIHBE<T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    /// Stores the interval for each message.
    local_table: HashMap<T, Range<u64>>,
}

/// The encoder for BHE.
#[derive(Debug, Clone)]
pub struct EncoderBHE;

impl<T> HomophoneEncoder<T> for EncoderIHBE<T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    fn initialize(&mut self, messages: &Vec<T>, advantage: f64) {
        if messages.is_empty() {
            return;
        }

        self.local_table.clear();
        // Construct a histogram from messages.
        let histogram = build_histogram(messages);
        // Also, compute the cumulative frequency for each message.
        let mut sum = 0f64;
        let n = messages.len();
        let mut cumulative_frequency = vec![0f64];
        for item in histogram.iter() {
            sum += item.1 as f64 / n as f64;
            cumulative_frequency.push(sum);
        }

        // f_{D}(m_1).
        let most_frequent = histogram.first().unwrap().1 as f64 / n as f64;
        let log_inner =
            f64::sqrt(n as f64) / (2.0 * f64::sqrt(2.0 * PI) * advantage * most_frequent);
        let r = log_inner.log2().ceil();
        let pow2_r = 2f64.powf(r);

        // Construct the local table.
        for item in cumulative_frequency.iter().enumerate() {
            let lhs = (pow2_r * cumulative_frequency.get(item.0).unwrap()).round() as u64;
            let rhs = (pow2_r * cumulative_frequency.get(item.0 + 1).unwrap()).round() as u64;
            let range = lhs..rhs;
            self.local_table
                .insert(histogram.get(item.0).unwrap().0.clone(), range);
        }
    }

    fn encode(&mut self, message: &T) -> Vec<u8> {
        todo!()
    }

    fn decode(&mut self, message: &[u8]) -> Vec<u8> {
        todo!()
    }
}

impl<T> HomophoneEncoder<T> for EncoderBHE
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    fn encode(&mut self, message: &T) -> Vec<u8> {
        todo!()
    }

    fn decode(&mut self, message: &[u8]) -> Vec<u8> {
        todo!()
    }
}

impl<T> ContextLPFSE<T>
where
    T: Hash + ToString + Eq + Debug + Clone,
{
    pub fn new(advantage: f64, encoder: Box<dyn HomophoneEncoder<T>>) -> Self {
        Self {
            advantage,
            key: Vec::new(),
            _marker: PhantomData,
            encoder,
        }
    }
}

impl<T> FrequencySmoothing<T> for ContextLPFSE<T>
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

        let homophone = self.encoder.encode(message);
        let nonce = Nonce::from_slice(b"0");
        let ciphertext = match aes.encrypt(nonce, homophone.as_slice()) {
            Ok(ciphertext) => ciphertext,
            Err(e) => {
                panic!(
                    "[-] Error encrypting the message due to {:?}.",
                    e.to_string()
                );
            }
        };
        ciphertexts.push(ciphertext);

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
        let plaintext = match aes.decrypt(nonce, ciphertext) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                panic!(
                    "[-] Error decrypting the message due to {:?}.",
                    e.to_string()
                );
            }
        };

        self.encoder.decode(&plaintext)
    }
}
