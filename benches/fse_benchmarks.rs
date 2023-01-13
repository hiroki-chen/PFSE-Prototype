use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use fse::{
    fse::{exponential, BaseCrypto, PartitionFrequencySmoothing},
    lpfse::{ContextLPFSE, EncoderBHE, EncoderIHBE},
    pfse::ContextPFSE,
    util::{read_csv, SizeAllocateed},
};

criterion_group! {
  name = fse_benches_real;
  config = Criterion::default().significance_level(0.1).sample_size(10);
  targets = pfse_bench_on_real, lpfse_ihbe_on_real, lpfse_bhe_on_real
}

criterion_main!(fse_benches_real);

fn pfse_bench_on_real(c: &mut Criterion) {
    let vec = read_csv("./data/test.csv", "order_number").unwrap();

    // Benchmark with different input sizes.
    let mut group = c.benchmark_group("pfse_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        let mut ctx = ContextPFSE::default();
        let slice = &vec[..size];
        ctx.key_generate();
        ctx.set_params(0.25, 1.0, 2_f64.powf(-12_f64));
        ctx.partition(slice, &exponential);
        ctx.transform();

        println!(
            "The local size is {} bytes.",
            ctx.get_local_table().size_allocated()
        );

        let id = format!("{}_{}", "pfse_benchmark", size);
        let bytes_size = std::mem::size_of_val(slice) as u64;
        group.throughput(Throughput::Elements(bytes_size));
        group.bench_function(&id, |b| b.iter(|| ctx.smooth()));
    }
    group.finish();
}

fn lpfse_ihbe_on_real(c: &mut Criterion) {
    let vec = read_csv("./data/test.csv", "order_number").unwrap();

    let mut group = c.benchmark_group("lpfse_ihbe_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        let slice = &vec[..size];
        let mut ctx =
            ContextLPFSE::new(2f64.powf(-10_f64), Box::new(EncoderIHBE::new()));
        ctx.key_generate();
        ctx.initialize(slice, "", "", false);
        ctx.store("./data/summary_ihbe.txt").unwrap();

        let id = format!("{}_{}", "lpfse_ihbe_benchmark", size);
        let bytes_size = std::mem::size_of_val(slice) as u64;
        group.throughput(Throughput::Elements(bytes_size));
        group.bench_function(&id, |b| {
            b.iter(|| {
                for message in slice.iter() {
                    ctx.encrypt(message).unwrap();
                }
            })
        });
    }
    group.finish();
}

fn lpfse_bhe_on_real(c: &mut Criterion) {
    let vec = read_csv("./data/test.csv", "order_number").unwrap();

    let mut group = c.benchmark_group("lpfse_bhe_bench_on_real");
    for size in [100, 1000, 10000, 100000, 1000000] {
        let slice = &vec[..size];
        let mut ctx =
            ContextLPFSE::new(2f64.powf(-10_f64), Box::new(EncoderBHE::new()));
        ctx.key_generate();
        ctx.initialize(slice, "", "", false);
        ctx.store("./data/summary_bhe.txt").unwrap();

        println!("The local size is {}.", ctx.get_encoder().size_allocated());

        let id = format!("{}_{}", "lpfse_bhe_benchmark", size);
        let bytes_size = std::mem::size_of_val(slice) as u64;
        group.throughput(Throughput::Elements(bytes_size));
        group.bench_function(&id, |b| {
            b.iter(|| {
                for message in slice.iter() {
                    ctx.encrypt(message).unwrap();
                }
            })
        });
    }
    group.finish();
}
