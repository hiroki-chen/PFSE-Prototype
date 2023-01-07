#![allow(non_snake_case)]

#[cfg(feature = "attack")]
pub mod attack;
pub mod context;
pub mod fse;

// Re-export
pub use context::*;

mod test {

    use std::f64::consts::E;
    #[allow(unused)]
    fn exp(param: f64, index: usize) -> f64 {
        param * E.powf(-param * index as f64)
    }

    #[test]
    fn test_partition() {
        use crate::{fse::FrequencySmoothing, FSEContext};

        let vec = vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 2, 1, 2, 3, 4, 2, 2, 3];
        let mut ctx = FSEContext::<i32>::default();
        ctx.key_generate(16);
        ctx.set_params(1.0, 1.0, 0.01);
        ctx.partition(vec, &exp);
    }
}
