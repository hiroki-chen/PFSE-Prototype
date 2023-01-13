//! This module mainly implements a baseline deterministic encryption algorithm that does NOT hide the frequency
//! of the message dataset it receives.

use std::{fmt::Debug, marker::PhantomData};

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose, Engine};
use rand_core::OsRng;

use crate::fse::{AsBytes, BaseCrypto};

#[derive(Debug)]
pub struct ContextNative<T>
where
    T: AsBytes + Debug,
{
    /// The secret key for symmetric encryption.
    key: Vec<u8>,
    /// Marker.
    _marker: PhantomData<T>,
}

impl<T> ContextNative<T>
where
    T: AsBytes + Debug,
{
    pub fn new() -> Self {
        Self {
            key: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<T> Default for ContextNative<T>
where
    T: AsBytes + Debug,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> BaseCrypto<T> for ContextNative<T>
where
    T: AsBytes + Debug,
{
    fn key_generate(&mut self) {
        self.key.clear();
        self.key = Aes256Gcm::generate_key(OsRng).to_vec();
    }

    fn encrypt(&self, message: &T) -> Option<Vec<Vec<u8>>> {
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
        let ciphertext = match aes.encrypt(nonce, message.as_bytes()) {
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
