#![allow(non_snake_case)]

pub mod context;
pub mod fse;

// Re-export
pub use context::*;

mod test {

    #[test]
    fn test_partition() {
        use crate::{fse::FrequencySmoothing, FSEContext};

        let vec = vec![1, 1, 1, 2, 2, 3];
        let mut ctx = FSEContext::<i32>::default();
        ctx.key_generate(16);
        ctx.set_params(0.5);
        ctx.partition(vec);
    }
}
