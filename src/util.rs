//! Utility module that mainly implements the filesystem, networking, database and some other intefaces.

use std::{
    collections::HashMap,
    fs::File,
    hash::Hash,
    io::{BufRead, BufReader, Result, Write},
};

use crate::fse::HistType;

pub fn read_file(path: &str) -> Result<Vec<String>> {
    let mut strings = Vec::new();
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        strings.push(line?);
    }

    Ok(strings)
}

pub fn write_file(path: &str, content: &[u8]) -> Result<()> {
    File::open(path)?.write_all(content)
}

/// Construct an ordered histogram vector from raw histogram
pub fn build_histogram_vec<T>(histogram: &HashMap<T, usize>) -> Vec<HistType<T>>
where
    T: Hash + Eq + Clone,
{
    // Convert histogram into vector that is ordered by frequency.
    let mut histogram_vec = Vec::new();
    histogram
        .iter()
        .for_each(|(key, &frequency)| histogram_vec.push((key.clone(), frequency)));
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
pub fn compute_cdf<T>(index: usize, histogram: &Vec<HistType<T>>, num: usize) -> f64 {
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
