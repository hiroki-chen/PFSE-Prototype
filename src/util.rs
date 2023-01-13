//! Utility module that mainly implements the filesystem, networking, and some other intefaces.

use std::{
    collections::HashMap,
    fmt::Debug,
    fs::File,
    hash::Hash,
    io::{BufRead, BufReader, Write},
};

use csv::ReaderBuilder;

use crate::{
    fse::{HistType, Random, ValueType, DEFAULT_RANDOM_LEN},
    Result,
};

pub fn read_file(path: &str) -> Result<Vec<String>> {
    let mut strings = Vec::new();
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        strings.push(line?);
    }

    Ok(strings)
}

/// Parse a CSV file and read the corresponding column.
pub fn read_csv(path: &str, column_name: &str) -> Result<Vec<String>> {
    let mut reader = ReaderBuilder::new().has_headers(true).from_path(path)?;

    // Locate the target column.
    let index = reader
        .headers()
        .unwrap()
        .iter()
        .enumerate()
        .find(|&(_, str)| str == column_name)
        .unwrap()
        .0;
    let strings = reader
        .records()
        .map(|elem| {
            elem.unwrap()
                .iter()
                .enumerate()
                .find(|&(i, _)| i == index)
                .unwrap()
                .1
                .to_string()
        })
        .collect();

    Ok(strings)
}

pub fn write_file(path: &str, content: &[u8]) -> std::io::Result<()> {
    File::open(path)?.write_all(content)
}

/// Construct an ordered histogram vector from raw histogram
pub fn build_histogram_vec<T>(histogram: &HashMap<T, usize>) -> Vec<HistType<T>>
where
    T: Hash + Eq + Clone,
{
    // Convert histogram into vector that is ordered by frequency.
    let mut histogram_vec = Vec::new();
    histogram.iter().for_each(|(key, &frequency)| {
        histogram_vec.push((key.clone(), frequency))
    });
    // Second, sort the vector in descending order.
    histogram_vec.sort_by(|lhs, rhs| rhs.1.cmp(&lhs.1));
    histogram_vec
}

/// Construct a raw histogram represented by the `HashMap`.
pub fn build_histogram<T>(dataset: &[T]) -> HashMap<T, usize>
where
    T: Hash + Eq + Clone,
{
    let mut histogram = HashMap::<T, usize>::new();
    // Construct the histogram for `dataset`.
    for i in dataset.iter() {
        let entry = histogram.entry(i.clone()).or_insert(0);
        *entry = match entry.checked_add(1) {
            Some(val) => val,
            None => panic!("[-] Overflow detected."),
        };
    }

    histogram
}

/// A helper function that computes the `i`-th value of the CDF, given a histogram and element number.
pub fn compute_cdf<T>(
    index: usize,
    histogram: &Vec<HistType<T>>,
    num: usize,
) -> f64 {
    if index >= histogram.len() {
        println!("[-] Index {} out of bound!", index);
        return 0f64;
    }

    let mut sum = 0f64;
    for i in 0..index {
        sum += (histogram.get(i).unwrap().1 as f64) / num as f64;
    }

    sum
}

/// Pad the message dataset if the size does not match with the ciphertext dataset.
pub fn pad_auxiliary<T>(
    auxiliary: &mut Vec<HistType<T>>,
    ciphertexts: &Vec<HistType<Vec<u8>>>,
) where
    T: Random,
{
    if auxiliary.len() < ciphertexts.len() {
        let diff = ciphertexts.len() - auxiliary.len();

        for _ in 0..diff {
            let random_string = T::random(DEFAULT_RANDOM_LEN);
            // Always pad with minimal frequency so that we cause minimal harm to the accuracy.
            auxiliary.push((random_string, 1usize));
        }
    }
}

/// Compute the intersection of two arrays.
pub fn intersect<T>(lhs: &[T], rhs: &[T]) -> Vec<T>
where
    T: Eq + Clone,
{
    let mut intersection = Vec::new();

    // A very naive O(m * n) algorithm.
    for item in lhs.iter() {
        if rhs.iter().any(|e| e == item) {
            intersection.push(item.clone());
        }
    }

    intersection
}

/// For attacker only. This function computes the weight of each ciphertext in their **own** ciphertext set.
#[cfg(feature = "attack")]
pub fn compute_ciphertext_weight(
    ciphertext_sets: &[Vec<Vec<u8>>],
) -> HashMap<Vec<u8>, f64> {
    let mut weight_map = HashMap::new();

    for ciphertext_set in ciphertext_sets.iter() {
        let sum = ciphertext_set.len();
        for ciphertext in ciphertext_set.iter() {
            let count =
                ciphertext_set.iter().filter(|&e| e == ciphertext).count();
            let weight = count as f64 / sum as f64;
            weight_map.insert(ciphertext.clone(), weight);
        }
    }

    weight_map
}
