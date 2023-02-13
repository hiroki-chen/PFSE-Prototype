//! This module mainly implements a baseline deterministic encryption algorithm that does NOT hide the frequency
//! of the message dataset it receives.

use std::{collections::HashMap, fmt::Debug, hash::Hash, marker::PhantomData};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine};
use log::debug;
use rand_core::{OsRng, RngCore};

use crate::{
    db::{Connector, Data},
    fse::{AsBytes, BaseCrypto, Conn, FromBytes},
    util::SizeAllocated,
};

#[derive(Debug, Clone)]
pub struct ContextNative<T>
where
    T: AsBytes + FromBytes + Debug + Eq + Hash + Clone + SizeAllocated,
{
    /// The secret key for symmetric encryption.
    key: Vec<u8>,
    /// Connector to the database.
    conn: Option<Connector<Data>>,
    /// Whether we use RND.
    rnd: bool,
    /// A local table for nonce lookup.
    local_table: HashMap<T, Vec<Vec<u8>>>,
}

impl<T> ContextNative<T>
where
    T: AsBytes + FromBytes + Debug + Eq + Hash + Clone + SizeAllocated,
{
    pub fn new(rnd: bool) -> Self {
        Self {
            key: Vec::new(),
            conn: None,
            rnd,
            local_table: HashMap::new(),
        }
    }

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

impl<T> Default for ContextNative<T>
where
    T: AsBytes + FromBytes + Debug + Eq + Hash + Clone + SizeAllocated,
{
    fn default() -> Self {
        Self::new(false)
    }
}

impl<T> Conn for ContextNative<T>
where
    T: AsBytes + FromBytes + Debug + Eq + Hash + Clone + SizeAllocated,
{
    fn get_conn(&self) -> &Connector<Data> {
        self.conn.as_ref().unwrap()
    }
}

impl<T> SizeAllocated for ContextNative<T>
where
    T: AsBytes + FromBytes + Debug + Eq + Hash + Clone + SizeAllocated,
{
    fn size_allocated(&self) -> usize {
        self.local_table
            .iter()
            .map(|(k, v)| k.size_allocated() + v.size_allocated())
            .sum()
    }
}

impl<T> BaseCrypto<T> for ContextNative<T>
where
    T: AsBytes + FromBytes + Debug + Eq + Hash + Clone + SizeAllocated,
{
    fn key_generate(&mut self) {
        self.key.clear();
        self.key = Aes256Gcm::generate_key(OsRng).to_vec();
    }

    fn encrypt(&mut self, message: &T) -> Option<Vec<Vec<u8>>> {
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
        let nonce = match self.rnd {
            true => {
                let mut buf = vec![0u8; 12];
                OsRng.fill_bytes(&mut buf);
                let nonce = Nonce::clone_from_slice(buf.as_slice());
                self.local_table
                    .entry(message.clone())
                    .or_default()
                    .push(buf);

                nonce
            }
            false => Nonce::clone_from_slice(&[0u8; 12]),
        };
        let ciphertext = match aes.encrypt(&nonce, message.as_bytes()) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "[-] Error when encrypting the message due to {:?}",
                    e
                );
                return None;
            }
        };

        Some(vec![general_purpose::STANDARD_NO_PAD
            .encode(ciphertext)
            .into_bytes()])
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
        let plaintext = match aes.decrypt(nonce, decoded_ciphertext.as_slice())
        {
            Ok(v) => v,
            Err(e) => return None,
        };

        Some(plaintext)
    }

    fn search(&mut self, message: &T, name: &str) -> Option<Vec<T>> {
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

        if self.rnd {
            let nonces = self.local_table.get(message).unwrap();
            let ciphertexts = nonces
                .iter()
                .map(|e| {
                    let nonce = Nonce::from_slice(e);
                    let ciphertext =
                        aes.encrypt(nonce, message.as_bytes()).unwrap();
                    general_purpose::STANDARD_NO_PAD
                        .encode(ciphertext)
                        .into_bytes()
                })
                .collect::<Vec<_>>();
            debug!("Ciphertext size = {}", ciphertexts.len());
            self.search_impl(ciphertexts, name)
        } else {
            let ciphertext = self.encrypt(message).unwrap();
            debug!("Ciphertext size = {}", ciphertext.len());
            self.search_impl(ciphertext, name)
        }
    }
}
