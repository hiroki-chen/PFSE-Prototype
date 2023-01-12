#![allow(non_snake_case)]
#![allow(unused)]
#![deny(clippy::ptr_arg)]
#![deny(clippy::needless_borrow)]
#![deny(clippy::new_without_default)]
#![deny(clippy::needless_return)]

#[cfg(feature = "attack")]
pub mod attack;
pub mod db;
pub mod fse;
pub mod scheme;
pub mod util;

// Re-export
pub use scheme::*;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

mod test {
    const ADDRESS: &str = "mongodb://127.0.0.1:27017";
    const DB_NAME: &str = "bench";
    const PFSE_COLLECTION: &str = "pfse_collection";
    const LPFSE_BHE_COLLECTION: &str = "lpfse_bhe_collection";
    const LPFSE_IHBE_COLLECTION: &str = "lpfse_ihbe_collection";

    #[allow(unused)]
    fn exp(param: f64, index: usize) -> f64 {
        use std::f64::consts::E;
        param * E.powf(-param * index as f64)
    }

    #[test]
    fn test_partition() {
        use crate::db::Data;
        use crate::util::read_csv;
        use crate::{fse::FrequencySmoothing, fse::PartitionFrequencySmoothing, pfse::ContextPFSE};

        let vec = read_csv("./data/test.csv", "order_number").unwrap();
        let mut ctx = ContextPFSE::default();
        ctx.initialize_conn(ADDRESS, DB_NAME, false);
        ctx.key_generate();
        ctx.set_params(0.25, 1.0, 2_f64.powf(-12_f64));
        ctx.partition(&vec, &exp);
        ctx.transform();
        ctx.store("./data/summary.txt").unwrap();

        let documents = ctx
            .smooth()
            .into_iter()
            .enumerate()
            .map(|(id, ciphertext)| {
                let data = String::from_utf8(ciphertext).unwrap();
                Data { id, data }
            })
            .collect::<Vec<_>>();

        let conn = ctx.get_conn().as_ref().unwrap();
        conn.insert(documents, PFSE_COLLECTION);
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
        ctx.initialize(&vec, ADDRESS, DB_NAME, false);
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
        ctx.initialize(&vec, ADDRESS, DB_NAME, false);
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

    #[test]
    fn test_db() {
        use crate::pfse::ContextPFSE;

        let mut ctx = ContextPFSE::<String>::default();
        let doc = crate::db::Data {
            id: 0,
            data: "ooo".to_string(),
        };
        ctx.initialize_conn("mongodb://127.0.0.1:27017", "bench", true);
        ctx.get_conn()
            .as_ref()
            .unwrap()
            .insert(vec![doc], "test_collection")
            .unwrap();
    }
}
