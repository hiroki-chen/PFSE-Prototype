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
        use crate::util::read_csv;
        use crate::{fse::FrequencySmoothing, fse::PartitionFrequencySmoothing, pfse::ContextPFSE};

        let vec = read_csv("./data/test.csv", "order_number").unwrap();
        let mut ctx = ContextPFSE::default();
        ctx.key_generate();
        ctx.set_params(0.25, 1.0, 2_f64.powf(-12_f64));
        ctx.partition(&vec, &exp);
        ctx.transform();
        ctx.store("./data/summary.txt").unwrap();

        let ciphertexts = ctx
            .encrypt(&"1".to_string())
            .unwrap()
            .into_iter()
            .map(|elem| String::from_utf8(elem).unwrap())
            .collect::<Vec<String>>();
        println!("{:?}", ciphertexts);
    }

    #[test]
    fn test_ihbe() {
        use crate::util::read_csv;
        use crate::{
            fse::FrequencySmoothing,
            lpfse::{ContextLPFSE, EncoderIHBE},
        };
        let mut vec = read_csv("./data/test.csv", "order_number").unwrap();
        vec.sort();
        let mut ctx = ContextLPFSE::new(2f64.powf(-10_f64), Box::new(EncoderIHBE::new()));
        ctx.key_generate();
        ctx.initialize(&vec);
        ctx.store("./data/summary_ihbe.txt").unwrap();

        let mut ciphertexts = Vec::new();
        for message in vec.iter() {
            let ciphertext = ctx.encrypt(message).unwrap().remove(0);
            ciphertexts.push(String::from_utf8(ciphertext).unwrap());
        }

        let mut plaintexts = Vec::new();
        for ciphertext in ciphertexts.iter() {
            let plaintext = ctx.decrypt(ciphertext.as_bytes()).unwrap();
            plaintexts.push(String::from_utf8(plaintext).unwrap());
        }

        assert_eq!(plaintexts, vec);
    }

    #[test]
    fn test_bhe() {
        use crate::util::read_csv;
        use crate::{
            fse::FrequencySmoothing,
            lpfse::{ContextLPFSE, EncoderBHE},
        };

        let mut vec = read_csv("./data/test.csv", "order_number").unwrap();
        vec.sort();
        let mut ctx = ContextLPFSE::new(2f64.powf(-10_f64), Box::new(EncoderBHE::new()));
        ctx.key_generate();
        ctx.initialize(&vec);
        ctx.store("./data/summary_bhe.txt").unwrap();

        let mut ciphertexts = Vec::new();
        for message in vec.iter() {
            let ciphertext = ctx.encrypt(message).unwrap().remove(0);
            ciphertexts.push(String::from_utf8(ciphertext).unwrap());
        }

        let mut plaintexts = Vec::new();
        for ciphertext in ciphertexts.iter() {
            let plaintext = ctx.decrypt(ciphertext.as_bytes()).unwrap();
            plaintexts.push(String::from_utf8(plaintext).unwrap());
        }

        assert_eq!(plaintexts, vec);
    }

    #[test]
    fn test_read_csv() {
        use crate::util::read_csv;

        let path = "./data/test.csv";
        let column = "order_number";
        let strings = read_csv(path, column).unwrap();
        println!("{:?}", &strings[..10]);
    }
}
