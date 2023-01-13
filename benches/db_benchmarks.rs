use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use fse::{
    db::Data,
    fse::BaseCrypto,
    native::ContextNative,
    util::{read_csv, SizeAllocateed},
};
use rand::seq::SliceRandom;
use rand_core::OsRng;

const ADDRESS: &str = "mongodb://127.0.0.1:27017";
const DB_NAME: &str = "bench";
const PFSE_COLLECTION: &str = "pfse_collection";
const LPFSE_BHE_COLLECTION: &str = "lpfse_bhe_collection";
const LPFSE_IHBE_COLLECTION: &str = "lpfse_ihbe_collection";

//, pfse_bench_on_real, lpfse_ihbe_on_real, lpfse_bhe_on_real
criterion_group! {
  name = fse_benches_db_real;
  config = Criterion::default().significance_level(0.1).sample_size(100);
  targets = native_bench_on_real
}

fn native_bench_on_real(c: &mut Criterion) {
    let mut vec = read_csv("./data/test.csv", "order_number").unwrap();
    vec.shuffle(&mut OsRng);

    let mut group = c.benchmark_group("native_db_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        let mut ctx = ContextNative::new(false);
        let slice = &vec[..size];
        ctx.key_generate();
        ctx.initialize_conn(ADDRESS, DB_NAME, true);
        let ciphertexts = slice
            .iter()
            .map(|e| {
                String::from_utf8(ctx.encrypt(e).unwrap().remove(0)).unwrap()
            })
            .enumerate()
            .map(|(id, data)| Data { id, data })
            .collect::<Vec<_>>();
        println!(
            "The size of the ciphertext vector is {}",
            ciphertexts.size_allocated()
        );

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    let conn = ctx.get_conn().as_ref().unwrap();
                    conn.insert(ciphertexts.clone(), PFSE_COLLECTION).unwrap();
                    conn.drop_collection(PFSE_COLLECTION);
                })
            },
        );
    }
    group.finish();

    // TODO: Start another session for query performance evaluations.
}
