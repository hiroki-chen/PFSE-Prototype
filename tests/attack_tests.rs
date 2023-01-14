#[cfg(feature = "attack")]
mod attack_tests {
    #[test]
    pub fn test_mle_attack() {
        use fse::{
            attack::MLEAttacker,
            fse::BaseCrypto,
            fse::PartitionFrequencySmoothing,
            scheme::pfse::ContextPFSE,
            util::{compute_ciphertext_weight, read_csv_exact},
        };
        use rand::prelude::*;
        use rand_core::OsRng;
        use std::collections::HashMap;

        let mut attacker = MLEAttacker::<String>::new();

        let mut plaintexts =
        read_csv_exact("./data/test.csv", "order_number").unwrap();
        plaintexts.shuffle(&mut OsRng);
        plaintexts.truncate(10000);

        let mut ctx = ContextPFSE::default();
        ctx.key_generate();
        ctx.set_params(0.25, 1.0, 2_f64.powf(-4_f64));
        ctx.partition(&plaintexts, &fse::fse::exponential);
        ctx.transform();
        ctx.store("./data/summary_mle.txt").unwrap();

        // Encrypt.
        let mut ciphertexts = Vec::new();
        let mut ciphertext_sets = Vec::new();
        let mut correct = HashMap::new();
        plaintexts.dedup();
        for message in plaintexts.iter() {
            let mut ciphertext = ctx.encrypt(message).unwrap();
            correct.insert(message.clone(), {
                let mut v = ciphertext.clone();
                v.dedup();
                v
            });
            ciphertext_sets.push(ciphertext.clone());
            ciphertexts.append(&mut ciphertext);
        }

        let rate = attacker.attack(
            &correct,
            ctx.get_local_table(),
            &ciphertexts,
            &compute_ciphertext_weight(&ciphertext_sets),
        );
        println!("{}", rate);
    }
}
