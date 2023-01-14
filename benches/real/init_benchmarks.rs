use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use fse::{
    fse::{exponential, BaseCrypto, PartitionFrequencySmoothing},
    lpfse::{ContextLPFSE, EncoderBHE, EncoderIHBE},
    native::ContextNative,
    pfse::ContextPFSE,
    util::read_csv_exact,
};
use rand::seq::SliceRandom;
use rand_core::OsRng;

criterion_group! {
    name = fse_benches_init_real;
    config = Criterion::default().significance_level(0.1).sample_size(10);
    targets = dte_bench_on_real, pfse_bench_on_real, lpfse_ihbe_on_real, lpfse_bhe_on_real, rnd_bench_on_real
}

fn dte_bench_on_real(c: &mut Criterion) {
    let mut vec = read_csv_exact("./data/test.csv", "order_number").unwrap();
    vec.shuffle(&mut OsRng);

    let mut group = c.benchmark_group("dte_init_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        let mut ctx = ContextNative::new(false);
        let slice = &vec[..size];
        ctx.key_generate();

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    for message in slice.iter() {
                        ctx.encrypt(message).unwrap();
                    }
                })
            },
        );
    }
    group.finish();
}

fn pfse_bench_on_real(c: &mut Criterion) {
    let mut vec = read_csv_exact("./data/test.csv", "order_number").unwrap();
    vec.shuffle(&mut OsRng);

    // Benchmark with different input sizes.
    let mut group = c.benchmark_group("pfse_init_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        for lambda in [0.25, 0.5, 0.75, 1.0] {
            let slice = &vec[..size];

            group.throughput(Throughput::Elements(size as u64));
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("{}_{}", size, lambda)),
                &(size, lambda),
                |b, (_, lambda)| {
                    b.iter(|| {
                        let mut ctx = ContextPFSE::default();
                        ctx.key_generate();
                        ctx.set_params(*lambda, 1.0, 2_f64.powf(-10_f64));

                        ctx.partition(slice, &exponential);
                        ctx.transform();
                        ctx.smooth()
                    })
                },
            );
        }
    }
    group.finish();
}

fn lpfse_ihbe_on_real(c: &mut Criterion) {
    let mut vec = read_csv_exact("./data/test.csv", "order_number").unwrap();
    vec.shuffle(&mut OsRng);

    let mut group = c.benchmark_group("lpfse_ihbe_init_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        let slice = &vec[..size];

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    let mut ctx = ContextLPFSE::new(
                        2f64.powf(-10_f64),
                        Box::new(EncoderIHBE::new()),
                    );
                    ctx.key_generate();
                    ctx.initialize(slice, "", "", false);

                    for message in slice.iter() {
                        ctx.encrypt(message).unwrap();
                    }
                })
            },
        );
    }
    group.finish();
}

fn lpfse_bhe_on_real(c: &mut Criterion) {
    let mut vec = read_csv_exact("./data/test.csv", "order_number").unwrap();
    vec.shuffle(&mut OsRng);

    let mut group = c.benchmark_group("lpfse_bhe_init_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        let slice = &vec[..size];

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                let mut ctx = ContextLPFSE::new(
                    2f64.powf(-10_f64),
                    Box::new(EncoderBHE::new()),
                );
                ctx.key_generate();
                ctx.initialize(slice, "", "", false);

                b.iter(|| {
                    for message in slice.iter() {
                        ctx.encrypt(message).unwrap();
                    }
                })
            },
        );
    }
    group.finish();
}

fn rnd_bench_on_real(c: &mut Criterion) {
    let mut vec = read_csv_exact("./data/test.csv", "order_number").unwrap();
    vec.shuffle(&mut OsRng);

    let mut group = c.benchmark_group("rnd_init_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        let mut ctx = ContextNative::new(true);
        let slice = &vec[..size];
        ctx.key_generate();

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &size,
            |b, _| {
                b.iter(|| {
                    for message in slice.iter() {
                        ctx.encrypt(message).unwrap();
                    }
                })
            },
        );
    }

    group.finish();
}
