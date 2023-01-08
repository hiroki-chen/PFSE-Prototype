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

/// Construct a histogram for a dataset [T] and return an ordered histogram vector.
pub fn build_histogram<T>(dataset: &Vec<T>) -> Vec<HistType<T>>
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

    // Convert histogram into vector that is ordered by frequency.
    let mut histogram_vec = Vec::new();
    histogram
        .into_iter()
        .for_each(|(key, frequency)| histogram_vec.push((key, frequency)));
    // Second, sort the vector in descending order.
    histogram_vec.sort_by(|lhs, rhs| rhs.1.cmp(&lhs.1));
    histogram_vec
}
