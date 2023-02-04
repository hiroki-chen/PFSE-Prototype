//! This module implements the Weakly Randomized Encryption (WRE) proposed by Pouliot, Griffy, and Wright.
//!
//! They present a new efficiently searchable, easily deployable database encryption scheme that is provably
//! secure against inference attacks even when used with real, low-entropy data.

use std::{collections::HashMap, fmt::Debug, hash::Hash};

use aes_gcm::{Aes256Gcm, KeyInit};
use rand_core::OsRng;

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
    pub fn get_salt(&self, message: &T) -> (Vec<usize>, Vec<f64>) {
        // After the information is collected, one can use rand_distr::WeightedAliasIndex to sample a salt
        // from the multinomial distribution.
        todo!()
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

impl<T> BaseCrypto<T> for ContextWRE<T>
where
    T: Hash + AsBytes + FromBytes + Eq + Debug + Clone + SizeAllocated,
{
    fn key_generate(&mut self) {
        self.key = Aes256Gcm::generate_key(&mut OsRng).to_vec();
    }

    fn encrypt(&mut self, message: &T) -> Option<Vec<Vec<u8>>> {
        todo!()
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        todo!()
    }
}
