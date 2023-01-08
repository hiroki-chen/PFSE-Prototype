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
        println!("{:?}", ctx.encrypt(&1));
    }

    #[test]
    fn test_ihbe() {
        use crate::{
            fse::FrequencySmoothing,
            lpfse::{ContextLPFSE, EncoderIHBE},
        };
        let vec = vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 2, 1, 2, 3, 4, 2, 2, 3];
        let mut ctx = ContextLPFSE::<i32>::new(2f64.powf(-10 as f64), Box::new(EncoderIHBE::new()));
        ctx.key_generate();
        ctx.initialize(&vec);
        println!("{:02x?}", ctx.encrypt(&1));
    }
}
