use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use fse::{
    db::Data,
    fse::{exponential, BaseCrypto, Conn, PartitionFrequencySmoothing},
    lpfse::{ContextLPFSE, EncoderBHE, EncoderIHBE},
    native::ContextNative,
    pfse::ContextPFSE,
    util::read_csv_exact,
};
use rand::seq::SliceRandom;
use rand_core::OsRng;
use rand_distr::{Distribution, Uniform};

const ADDRESS: &str = "mongodb://127.0.0.1:27017";
const DB_NAME: &str = "bench";
const DTE_COLLECTION: &str = "dte_collection";
const RND_COLLECTION: &str = "rnd_collection";
const PFSE_COLLECTION: &str = "pfse_collection";
const LPFSE_BHE_COLLECTION: &str = "lpfse_bhe_collection";
const LPFSE_IHBE_COLLECTION: &str = "lpfse_ihbe_collection";

//, pfse_bench_on_real, lpfse_ihbe_on_real, lpfse_bhe_on_real
criterion_group! {
  name = fse_benches_query_real;
  config = Criterion::default().significance_level(0.1).sample_size(10);
  targets = dte_bench_on_real, pfse_bench_on_real
}

fn dte_bench_on_real(c: &mut Criterion) {
    let mut vec = read_csv_exact("./data/test.csv", "order_number").unwrap();
    vec.shuffle(&mut OsRng);

    let mut group = c.benchmark_group("dte_query_bench_on_real");
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
        let conn = ctx.get_conn();
        conn.insert(ciphertexts, DTE_COLLECTION).unwrap();

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    // Randomly select a message and search for it.
                    let idx = Uniform::new(0, size).sample(&mut OsRng);
                    let message = &slice[idx];
                    ctx.search(message, DTE_COLLECTION);
                })
            },
        );

        conn.drop_collection(DTE_COLLECTION);
    }
    group.finish();
}

fn pfse_bench_on_real(c: &mut Criterion) {
    let mut vec = read_csv_exact("./data/test.csv", "order_number").unwrap();
    vec.shuffle(&mut OsRng);

    // Benchmark with different input sizes.
    let mut group = c.benchmark_group("pfse_qeury_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        for lambda in [0.25, 0.5, 0.75, 1.0] {
            let slice = &vec[..size];
            let mut ctx = ContextPFSE::default();
            ctx.key_generate();
            ctx.set_params(lambda, 1.0, 2_f64.powf(-10_f64));
            ctx.initialize_conn(ADDRESS, DB_NAME, true);
            ctx.partition(slice, &exponential);
            ctx.transform();
            let ciphertexts = ctx
                .smooth()
                .into_iter()
                .enumerate()
                .map(|(id, data)| Data {
                    id,
                    data: String::from_utf8(data).unwrap(),
                })
                .collect::<Vec<_>>();
            let conn = ctx.get_conn();
            conn.insert(ciphertexts.clone(), PFSE_COLLECTION).unwrap();

            group.throughput(Throughput::Elements(size as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{}_{}", size, lambda)),
                &(size, lambda),
                |b, _| {
                    b.iter(|| {
                        // Randomly select a message and search for it.
                        let idx = Uniform::new(0, size).sample(&mut OsRng);
                        let message = &slice[idx];
                        ctx.search(message, DTE_COLLECTION);
                    })
                },
            );
            conn.drop_collection(PFSE_COLLECTION);
        }
    }
    group.finish();
}

fn lpfse_ihbe_bench_on_real(c: &mut Criterion) {
    let mut vec = read_csv_exact("./data/test.csv", "order_number").unwrap();
    vec.shuffle(&mut OsRng);

    let mut group = c.benchmark_group("lpfse_ihbe_insert_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        let slice = &vec[..size];
        let mut ctx =
            ContextLPFSE::new(2f64.powf(-10_f64), Box::new(EncoderIHBE::new()));
        ctx.key_generate();
        ctx.initialize(slice, ADDRESS, DB_NAME, true);

        let ciphertexts = slice
            .iter()
            .map(|e| {
                String::from_utf8(ctx.encrypt(e).unwrap().remove(0)).unwrap()
            })
            .enumerate()
            .map(|(id, data)| Data { id, data })
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    let conn = ctx.get_conn();
                    conn.insert(ciphertexts.clone(), LPFSE_IHBE_COLLECTION)
                        .unwrap();
                    conn.drop_collection(LPFSE_IHBE_COLLECTION);
                })
            },
        );
    }
    group.finish();
}

fn lpfse_bhe_bench_on_real(c: &mut Criterion) {
    let mut vec = read_csv_exact("./data/test.csv", "order_number").unwrap();
    vec.shuffle(&mut OsRng);

    let mut group = c.benchmark_group("lpfse_bhe_insert_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        let slice = &vec[..size];
        let mut ctx =
            ContextLPFSE::new(2f64.powf(-10_f64), Box::new(EncoderBHE::new()));
        ctx.key_generate();
        ctx.initialize(slice, ADDRESS, DB_NAME, true);

        let ciphertexts = slice
            .iter()
            .map(|e| {
                String::from_utf8(ctx.encrypt(e).unwrap().remove(0)).unwrap()
            })
            .enumerate()
            .map(|(id, data)| Data { id, data })
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    let conn = ctx.get_conn();
                    conn.insert(ciphertexts.clone(), LPFSE_BHE_COLLECTION)
                        .unwrap();
                    conn.drop_collection(LPFSE_BHE_COLLECTION);
                })
            },
        );
    }
    group.finish();
}

fn rnd_bench_on_real(c: &mut Criterion) {
    let mut vec = read_csv_exact("./data/test.csv", "order_number").unwrap();
    vec.shuffle(&mut OsRng);

    let mut group = c.benchmark_group("rnd_db_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        let mut ctx = ContextNative::new(true);
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

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    let conn = ctx.get_conn();
                    conn.insert(ciphertexts.clone(), RND_COLLECTION).unwrap();
                    conn.drop_collection(RND_COLLECTION);
                })
            },
        );
    }
    group.finish();
}
