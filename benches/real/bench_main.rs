use criterion::criterion_main;

pub mod init_benchmarks;
pub mod insert_benchmarks;
pub mod query_benchmarks;

criterion_main!(
    init_benchmarks::fse_benches_init_real,
    query_benchmarks::fse_benches_query_real,
    insert_benchmarks::fse_benches_insert_real,
);
