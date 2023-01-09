#![allow(non_snake_case)]
#![deny(clippy::ptr_arg)]
#![deny(clippy::needless_borrow)]
#![deny(clippy::new_without_default)]
#![deny(clippy::needless_return)]

#[cfg(feature = "attack")]
pub mod attack;
pub mod fse;
pub mod scheme;
pub mod util;

// Re-export
pub use scheme::*;

mod test {

    use std::f64::consts::E;

    #[allow(unused)]
    fn exp(param: f64, index: usize) -> f64 {
        param * E.powf(-param * index as f64)
    }

    #[test]
    fn test_partition() {
        use crate::{fse::FrequencySmoothing, fse::PartitionFrequencySmoothing, pfse::ContextPFSE};

        let vec = vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 2, 1, 2, 3, 4, 2, 2, 3];
        let mut ctx = ContextPFSE::<i32>::default();
        ctx.key_generate();
        ctx.set_params(1.0, 1.0, 0.01);
        ctx.partition(&vec, &exp);
        ctx.transform();

        let ciphertexts = ctx
            .encrypt(&1)
            .unwrap()
            .into_iter()
            .map(|elem| String::from_utf8(elem).unwrap())
            .collect::<Vec<String>>();
        println!("{:?}", ciphertexts);
    }

    #[test]
    fn test_ihbe() {
        use crate::{
            fse::FrequencySmoothing,
            lpfse::{ContextLPFSE, EncoderIHBE},
        };
        let mut vec = vec![
            1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 2, 1, 2, 3, 4, 2, 2, 3, 4, 4, 2, 2, 4, 5, 1, 2, 3,
        ];
        vec.sort();
        let mut ctx = ContextLPFSE::<i32>::new(2f64.powf(-10_f64), Box::new(EncoderIHBE::new()));
        ctx.key_generate();
        ctx.initialize(&vec);

        let mut ciphertexts = Vec::new();
        for message in vec.iter() {
            let ciphertext = ctx.encrypt(message).unwrap().remove(0);
            ciphertexts.push(String::from_utf8(ciphertext).unwrap());
        }

        let mut plaintexts = Vec::new();
        for ciphertext in ciphertexts.iter() {
            let plaintext = ctx.decrypt(ciphertext.as_bytes()).unwrap();
            plaintexts.push(
                String::from_utf8(plaintext)
                    .unwrap()
                    .parse::<i32>()
                    .unwrap(),
            );
        }

        assert_eq!(plaintexts, vec);
    }

    #[test]
    fn test_bhe() {
        use crate::{
            fse::FrequencySmoothing,
            lpfse::{ContextLPFSE, EncoderBHE},
        };

        let mut vec = vec![
            1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 2, 1, 2, 3, 4, 2, 2, 3, 4, 4, 2, 2, 4, 5, 1, 2, 3,
        ];
        vec.sort();
        let mut ctx = ContextLPFSE::new(2f64.powf(-10_f64), Box::new(EncoderBHE::new()));
        ctx.key_generate();
        ctx.initialize(&vec);

        let mut ciphertexts = Vec::new();
        for message in vec.iter() {
            let ciphertext = ctx.encrypt(message).unwrap().remove(0);
            ciphertexts.push(String::from_utf8(ciphertext).unwrap());
        }

        let mut plaintexts = Vec::new();
        for ciphertext in ciphertexts.iter() {
            let plaintext = ctx.decrypt(ciphertext.as_bytes()).unwrap();
            plaintexts.push(
                String::from_utf8(plaintext)
                    .unwrap()
                    .parse::<i32>()
                    .unwrap(),
            );
        }

        assert_eq!(plaintexts, vec);
    }
}
