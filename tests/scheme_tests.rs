mod scheme_tests {
    use fse::fse::Conn;
    use rand::seq::SliceRandom;

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
        use fse::db::Data;
        use fse::util::read_csv_exact;
        use fse::{
            fse::BaseCrypto, fse::PartitionFrequencySmoothing,
            pfse::ContextPFSE,
        };

        let vec = read_csv_exact("./data/test.csv", "order_number").unwrap();
        let mut ctx = ContextPFSE::default();
        ctx.initialize_conn(ADDRESS, DB_NAME, false);
        ctx.key_generate();
        ctx.set_params(&vec![0.25, 1.0, 2_f64.powf(-12_f64)]);
        ctx.partition(&vec, exp);
        ctx.transform();
        ctx.store("./data/summary.txt").unwrap();

        let documents = ctx
            .smooth()
            .into_iter()
            .enumerate()
            .map(|(_, ciphertext)| {
                let data = String::from_utf8(ciphertext).unwrap();
                Data { data }
            })
            .collect::<Vec<_>>();

        let conn = ctx.get_conn();
        conn.insert(documents, PFSE_COLLECTION).unwrap();
    }

    #[test]
    fn test_ihbe() {
        use fse::util::read_csv_exact;
        use fse::{
            fse::BaseCrypto,
            lpfse::{ContextLPFSE, EncoderIHBE},
        };
        let mut vec =
            read_csv_exact("./data/test.csv", "order_number").unwrap();
        vec.sort();
        let mut ctx =
            ContextLPFSE::new(2f64.powf(-10_f64), Box::new(EncoderIHBE::new()));
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
        use fse::util::read_csv_exact;
        use fse::{
            fse::BaseCrypto,
            lpfse::{ContextLPFSE, EncoderBHE},
        };

        let mut vec =
            read_csv_exact("./data/test.csv", "order_number").unwrap();
        vec.sort();
        let mut ctx =
            ContextLPFSE::new(2f64.powf(-10_f64), Box::new(EncoderBHE::new()));
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
        use fse::util::read_csv_exact;

        let path = "./data/test.csv";
        let column = "order_number";
        let strings = read_csv_exact(path, column).unwrap();
        println!("{:?}", &strings[..10]);
    }

    #[test]
    fn test_db() {
        use fse::pfse::ContextPFSE;
        use mongodb::bson::*;

        let mut ctx = ContextPFSE::<String>::default();
        let doc = fse::db::Data {
            data: "ooo".to_string(),
        };
        ctx.initialize_conn("mongodb://127.0.0.1:27017", "bench", true);
        let conn = ctx.get_conn();
        conn.insert(vec![doc], "test_collection").unwrap();

        let mut doc = Document::new();
        let mut test_key = Document::new();
        test_key.insert("data", "ooo");
        doc.insert("$or", vec![test_key]);

        println!("{}", conn.size("test_collection"));

        println!(
            "{:?}",
            conn.search(doc, "test_collection")
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_wre() {
        use rand_core::OsRng;
        use fse::util::read_csv_exact;
        use fse::{fse::BaseCrypto, wre::ContextWRE};

        let mut vec =
            read_csv_exact("./data/test.csv", "order_number").unwrap();
        vec.shuffle(&mut OsRng);
        let messages = &vec[..100];

        let mut ctx = ContextWRE::new(10);
        ctx.key_generate();
        ctx.initialize(messages, ADDRESS, DB_NAME, true);

        let ciphertexts = messages
            .iter()
            .map(|message| ctx.encrypt(message).unwrap())
            .collect::<Vec<_>>();
    }
}
