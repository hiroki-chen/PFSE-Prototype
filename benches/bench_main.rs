use criterion::criterion_main;

mod init_benchmarks;
mod insertion_benchmarks;

criterion_main!(
    init_benchmarks::fse_benches_init_real,
    insertion_benchmarks::fse_benches_insertion_real
);
