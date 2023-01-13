# Partition-Based Frequency Smoothing Encryption

This repo is a reference implementation of the partition-based FSE scheme that reduces the overheads of storage as well as the execution time.
The code is written as a library in **stable** Rust.

## MSRV

The Minimum Supported Rust Version is 1.65.0.

## Testing and Benchmarking

This crate provides with a test suite in `./test` and can be exeucted by `cargo test`. Also, we use the `criterion-rs` crate to enable benchmarking in stable Rust.
