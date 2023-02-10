//! This module implements the Weakly Randomized Encryption (WRE) proposed by Pouliot, Griffy, and Wright.
//!
//! They present a new efficiently searchable, easily deployable database encryption scheme that is provably
//! secure against inference attacks even when used with real, low-entropy data.

use std::{collections::HashMap, fmt::Debug, hash::Hash};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use log::error;
use rand::seq::SliceRandom;
use rand_core::OsRng;
use rand_distr::{Distribution, Exp, Uniform, WeightedAliasIndex};

use crate::{
    db::{Connector, Data},
    fse::{AsBytes, BaseCrypto, Conn, FromBytes},
    util::{build_histogram, build_histogram_vec, SizeAllocated},
};

#[derive(Debug)]
pub struct ContextWRE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + SizeAllocated,
{
    /// The parameter for the Poisson salt allocation.
    lambda: usize,
    /// A random key.
    key: Vec<u8>,
    /// The connector.
    conn: Option<Connector<Data>>,
    /// The frequency table.
    local_table: HashMap<T, f64>,
}

impl<T> ContextWRE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + SizeAllocated,
{
    pub fn new(lambda: usize) -> Self {
        Self {
            lambda,
            key: Vec::new(),
            conn: None,
            local_table: HashMap::new(),
        }
    }

    /// Initializes the struct.
    pub fn initialize(
        &mut self,
        messages: &[T],
        address: &str,
        db_name: &str,
        drop: bool,
    ) {
        // Initialize the local table.
        let histogram = build_histogram(messages);
        let sum = histogram.iter().map(|(k, v)| v).sum::<usize>();
        self.local_table = histogram
            .into_iter()
            .map(|(k, v)| {
                let frequency = v as f64 / sum as f64;
                (k, frequency)
            })
            .collect();

        // Initialize the connector.
        if let Ok(conn) = Connector::new(address, db_name, drop) {
            self.conn = Some(conn);
        }
    }

    /// Get the Poisson salt. The fixed Poisson WRE approach above generated randomized search tags
    /// for each plaintext. However, the scheme has security flaw: When the adversary has the frequencies
    /// of all search tags and knows PM, Lacharite and Paterson pointed out another possible attack,
    /// wherein the adversary finds a set of search tags whose counts sum up to the expected count for
    /// a (set of) target plaintext(s). The adversary might then reasonably conclude that those search
    /// tags all represent encryptions of the given plaintext(s).
    ///
    /// Thus, they use the bucketized Poisson salt allocation scheme to prevent such an attack.
    ///
    /// This function returns the salt hashmap where the key is the salt and the value is the weight of
    /// this salt. The algorithm them samples a salt according to the frequency of the hashmap.
    #[deprecated]
    fn get_salt_set(&self, message: &T) -> (Vec<usize>, Vec<f64>) {
        let mut s = 0usize;
        let mut word_frequency = Vec::new();
        let mut salts = Vec::new();
        let mut total = 0f64;
        let mut weights = HashMap::new();

        // The exponential distribution Exp(lambda).
        let exp_distribution = Exp::new(self.lambda as f64).unwrap();

        while total < 1.0 {
            s += 1;
            let weight = exp_distribution.sample(&mut OsRng);
            weights.insert(s, weight);
            total += weight;
        }

        weights.entry(s).and_modify(|frequency| {
            *frequency -= total - 1.0;
        });

        // Get a psedorandom permutation from message (histogram)
        let mut m_prime = self
            .local_table
            .iter()
            .map(|(k, v)| (k, *v))
            .collect::<Vec<_>>();
        m_prime.shuffle(&mut OsRng);
        let idx = match m_prime.iter().position(|&(k, v)| k == message) {
            Some(idx) => idx,
            // Does not exists, this should be an error.
            None => return (vec![], vec![]),
        };
        // fr = P_M(m_1) + ... + PM(m_{x − 1}) where m = mx (<- the current message.)
        let fr = match idx {
            0 => m_prime.first().unwrap().1,
            idx => m_prime[..idx].iter().map(|&(k, v)| v).sum::<f64>().min(1.0),
        };

        let mut i = 0usize;
        let mut cdf = 0f64;
        while cdf < fr {
            cdf += *weights.get(&i).unwrap_or(&0.0);
            i += 1;
        }

        weights
            .entry(i)
            .and_modify(|frequency| *frequency = cdf - fr);
        cdf = fr;
        i -= 1;
        let message_frequency = match self.local_table.get(message) {
            Some(&v) => v,
            None => return (vec![], vec![]),
        };

        while cdf < (fr + message_frequency).min(1.0) {
            let weight = *weights.get(&i).unwrap();
            word_frequency.push(weight / fr);
            salts.push(i);
            println!("cdf = {cdf}, fr = {fr}, message_frequency = {message_frequency}, weight = {weight}, i = {i}");
            i += 1;
            cdf += *weights.get(&i).unwrap_or(&0.0);
        }

        if cdf > fr + message_frequency {
            let diff = fr + message_frequency - cdf;
            let weight = *weights.get(&i).unwrap_or(&0.0);
            word_frequency.push((weight - diff) / fr);
            salts.push(i);
        }

        // After the information is collected, one can use rand_distr::WeightedAliasIndex to sample a salt
        // from the multinomial distribution.
        (salts, word_frequency)
    }

    /// Sample a salt according to the multinomial distribution.
    fn get_salt(&self, weights: &(Vec<usize>, Vec<f64>)) -> usize {
        let distribution = WeightedAliasIndex::new(weights.1.clone()).unwrap();
        let index = distribution.sample(&mut OsRng);
        *weights.0.get(index).unwrap()
    }
}

impl<T> Conn for ContextWRE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + SizeAllocated,
{
    fn get_conn(&self) -> &Connector<Data> {
        self.conn.as_ref().unwrap()
    }
}

impl<T> SizeAllocated for ContextWRE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + SizeAllocated,
{
    fn size_allocated(&self) -> usize {
        unimplemented!()
    }
}

impl<T> BaseCrypto<T> for ContextWRE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + SizeAllocated,
{
    fn key_generate(&mut self) {
        self.key = Aes256Gcm::generate_key(&mut OsRng).to_vec();
    }

    fn encrypt(&mut self, message: &T) -> Option<Vec<Vec<u8>>> {
        let salts = self.get_salt_set(message);
        let salt = self.get_salt(&salts);
        let aes = match Aes256Gcm::new_from_slice(&self.key) {
            Ok(aes) => aes,
            Err(e) => {
                error!(
                    "Error constructing the AES context due to {:?}.",
                    e.to_string()
                );
                return None;
            }
        };

        let nonce = Nonce::from_slice(&[0u8; 12]);
        match aes.encrypt(nonce, salt.to_le_bytes().as_slice()) {
            Ok(ciphertext) => Some(vec![ciphertext]),
            Err(e) => {
                error!(
                    "Error encrypting the message due to {:?}.",
                    e.to_string()
                );
                None
            }
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        todo!()
    }
}
