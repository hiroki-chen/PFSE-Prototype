#[cfg(feature = "attack")]
mod attack_tests {

    #[test]
    pub fn test_lp_optimization() {
        use fse::attack::LpAttacker;
        use fse::fse::SymmetricEncryption;
        use fse::scheme::naive::ContextNative;
        use std::collections::HashMap;

        let mut attacker = LpAttacker::<String>::new(2);
        let auxiliary = vec![1, 2, 3, 4, 1, 2, 3, 4, 4, 4, 4, 2, 2, 3, 4]
            .into_iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>();

        // Encrypt.
        let mut ctx = ContextNative::new();
        let mut ciphertexts = Vec::new();
        let mut correct = HashMap::new();
        ctx.key_generate();
        for message in auxiliary.iter() {
            let ciphertext = ctx.encrypt(message).unwrap().remove(0);
            correct.insert(message.clone(), ciphertext.clone());
            ciphertexts.push(ciphertext);
        }

        let rate = attacker.attack(&correct, &auxiliary, &ciphertexts);
        assert!(rate <= 1.0);
        println!("{}", rate);
    }
}
