//! Utility module that mainly implements the filesystem, networking, and some other intefaces.

use std::{
    collections::HashMap,
    fmt::Debug,
    fs::File,
    hash::Hash,
    io::{BufRead, BufReader, Write},
};

use array_tool::vec::Intersect;
use csv::{Reader, ReaderBuilder};
use log::error;
use rand_core::OsRng;
use rand_distr::{Distribution, Normal, Zipf};

use crate::{
    fse::{HistType, Random, ValueType, DEFAULT_RANDOM_LEN},
    Result,
};

/// A helper trait that defines an interface used to calculate the allocated size of an object.
pub trait SizeAllocated {
    fn size_allocated(&self) -> usize;
}

pub fn read_file(path: &str) -> Result<Vec<String>> {
    let mut strings = Vec::new();
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        strings.push(line?);
    }

    Ok(strings)
}

/// Read a whole csv file.
fn read_csv(path: &str) -> Result<Reader<File>> {
    Ok(ReaderBuilder::new().has_headers(true).from_path(path)?)
}
/// Read the corresponding column.
fn read_column(
    reader: &mut Reader<File>,
    column_name: &str,
) -> Result<Vec<String>> {
    // Locate the target column.
    let index = match reader
        .headers()
        .unwrap()
        .iter()
        .enumerate()
        .find(|&(_, str)| str == column_name)
    {
        Some(index) => index.0,
        None => return Err("Not found.".into()),
    };

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

/// Parse a CSV file and read multiple columns.
pub fn read_csv_multiple(
    path: &str,
    column_names: &[String],
) -> Result<Vec<Vec<String>>> {
    let mut reader = read_csv(path)?;

    let mut strings = Vec::new();
    for column_name in column_names.iter() {
        strings.push(read_column(&mut reader, column_name)?);
    }

    Ok(strings)
}

/// Parse a CSV file and read the corresponding column.
pub fn read_csv_exact(path: &str, column_name: &str) -> Result<Vec<String>> {
    let mut reader = read_csv(path)?;

    read_column(&mut reader, column_name)
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
        error!("Index {} out of bound!", index);
        return 0f64;
    }

    let mut sum = 0f64;
    for i in 0..index {
        sum += (histogram.get(i).unwrap().1 as f64) / num as f64;
    }

    sum
}

/// Pad the message dataset if the size does not match with the ciphertext dataset.
#[cfg(feature = "attack")]
pub fn pad_auxiliary<T>(
    auxiliary: &mut Vec<(T, f64, usize)>,
    ciphertexts: &Vec<HistType<Vec<u8>>>,
) where
    T: Random,
{
    if auxiliary.len() < ciphertexts.len() {
        let diff = ciphertexts.len() - auxiliary.len();

        for _ in 0..diff {
            let random_string = T::random(DEFAULT_RANDOM_LEN);
            // Always pad with minimal frequency so that we cause minimal harm to the accuracy.
            auxiliary.push((random_string, 10e-8, 1usize));
        }
    }
}

/// For attacker only. This function computes the weight of each ciphertext in their **own** ciphertext set.
#[cfg(feature = "attack")]
#[deprecated]
pub fn compute_ciphertext_weight<T>(
    ciphertext_sets: &HashMap<T, Vec<Vec<u8>>>,
) -> HashMap<Vec<u8>, f64>
where
    T: Hash + Eq,
{
    let mut weight_map = HashMap::new();

    for (_, ciphertext_set) in ciphertext_sets.iter() {
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

/// Compute the intersection of two vectors.
///
/// The reason why we do not want to use `array_tool::vec::Intersect` is that it is `slow` because
/// it does not apply any optimization on sortable elements. If the elements in the vector implement
/// [`std::cmp::PartialOrd`] and [`std::cmp::PartialEq`], we can compute the intersection in O(nlogn)
/// time while the naive algorithm requires O(mn) time, where `m, n` denote the lengths of the vectors.
pub fn intersect<T>(lhs: &[T], rhs: &[T]) -> Vec<T>
where
    T: Ord + Eq + Clone + Debug,
{
    // Sort these two arrays first. => O(nlogn)
    let lhs_vec = {
        let mut lhs_vec = lhs.to_vec();
        lhs_vec.sort();
        lhs_vec
    };
    let rhs_vec = {
        let mut rhs_vec = rhs.to_vec();
        rhs_vec.sort();
        rhs_vec
    };

    let mut ans = vec![];
    // Double pointers to accelerate finding => O(n)
    let mut i = 0usize;
    let mut j = 0usize;
    while i < lhs_vec.len() && j < rhs_vec.len() {
        if lhs_vec[i] == rhs_vec[j] {
            ans.push(lhs_vec[i].clone());
            i += 1;
            j += 1;
        } else if lhs_vec[i] > rhs_vec[j] {
            while j < rhs_vec.len() && lhs_vec[i] > rhs_vec[j] {
                j += 1;
            }
        } else {
            while i < lhs_vec.len() && lhs_vec[i] < rhs_vec[j] {
                i += 1;
            }
        }
    }

    ans
}

/// Generate a synthetic dataset from a normal distribution for testing.
pub fn generate_synthetic_normal<T>(
    support: &[T],
    mean: usize,
    deviation: f64,
) -> Vec<T>
where
    T: Clone,
{
    let normal = Normal::new(mean as f64, deviation).unwrap();
    generate_dataset(normal, support)
}

/// Generate a synthetic dataset from a Zipf distribution for testing.
pub fn generate_synthetic_zipf<T>(support: &[T], s: f64) -> Vec<T>
where
    T: Clone,
{
    let zipf = Zipf::new(support.len() as u64, s).unwrap();
    generate_dataset(zipf, support)
}

fn generate_dataset<T>(dist: impl Distribution<f64>, support: &[T]) -> Vec<T>
where
    T: Clone,
{
    let mut dataset = Vec::new();
    for item in support.iter() {
        let mut val = 0usize;
        loop {
            val = dist.sample(&mut OsRng).round() as usize;
            if val != 0 {
                break;
            }
        }
        dataset.append(&mut vec![item.clone(); val]);
    }
    dataset
}
