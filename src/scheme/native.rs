//! This module mainly implements a baseline deterministic encryption algorithm that does NOT hide the frequency
//! of the message dataset it receives.

use std::{fmt::Debug, marker::PhantomData};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine};
use rand_core::{OsRng, RngCore};

use crate::{
    db::{Connector, Data},
    fse::{AsBytes, BaseCrypto, Conn, FromBytes},
};

#[derive(Debug, Clone)]
pub struct ContextNative<T>
where
    T: AsBytes + FromBytes + Debug,
{
    /// The secret key for symmetric encryption.
    key: Vec<u8>,
    /// Connector to the database.
    conn: Option<Connector<Data>>,
    /// Whether we use RND.
    rnd: bool,
    /// Marker.
    _marker: PhantomData<T>,
}

impl<T> ContextNative<T>
where
    T: AsBytes + FromBytes + Debug,
{
    pub fn new(rnd: bool) -> Self {
        Self {
            key: Vec::new(),
            conn: None,
            rnd,
            _marker: PhantomData,
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
    T: AsBytes + FromBytes + Debug,
{
    fn default() -> Self {
        Self::new(false)
    }
}

impl<T> Conn for ContextNative<T>
where
    T: AsBytes + FromBytes + Debug,
{
    fn get_conn(&self) -> &Connector<Data> {
        self.conn.as_ref().unwrap()
    }
}

impl<T> BaseCrypto<T> for ContextNative<T>
where
    T: AsBytes + FromBytes + Debug,
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
                Nonce::clone_from_slice(buf.as_slice())
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
            Err(e) => {
                println!(
                    "[-] Error when encrypting the message due to {:?}",
                    e
                );
                return None;
            }
        };

        Some(plaintext)
    }
}
