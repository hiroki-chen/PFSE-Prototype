use criterion::criterion_main;

mod db_benchmarks;
mod init_benchmarks;

criterion_main!(
    init_benchmarks::fse_benches_init_real,
    db_benchmarks::fse_benches_db_real,
);
