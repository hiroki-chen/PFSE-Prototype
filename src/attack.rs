//! This module mainly implements the inference-attack family. This contains the frequency analysis, l_p optimization as well as
//! the (scaled) MLE attack. This module should be enabled by the `attack` (optional) feature.

use std::{collections::HashMap, hash::Hash, marker::PhantomData};

use pathfinding::{
    kuhn_munkres::kuhn_munkres_min,
    prelude::{Matrix, Weights},
};

use crate::{
    fse::{HistType, Random},
    util::{build_histogram, build_histogram_vec, pad_auxiliary},
};

/// An attacker that uses the $\ell_{p}$-norm to optimize the attack. The basic idea is find an as-signment from ciphertexts to
/// plaintexts that minimizes a given cost function, chosen here to be the $\ell_{p}$ distance between the histograms of the dataset.
#[derive(Debug)]
pub struct LpAttacker<T>
where
    T: Eq + Clone + Hash + Random,
{
    /// The `p` norm.
    p: usize,
    /// The assignment.
    assignment: Option<Vec<usize>>,
    /// A marker.
    _marker: PhantomData<T>,
}

impl<T> LpAttacker<T>
where
    T: Eq + Clone + Hash + Random,
{
    pub fn new(p: usize) -> Self {
        Self {
            p,
            assignment: None,
            _marker: PhantomData,
        }
    }

    /// Perform the lp optimization attack and store the assignment within itself.
    /// Finally it outputs the recovery rate.
    pub fn attack(
        &mut self,
        correct: &HashMap<T, Vec<u8>>,
        raw_auxiliary: &Vec<T>,
        raw_ciphertexts: &Vec<Vec<u8>>,
    ) -> f64 {
        // First, build the histograms for the two datasets.
        let mut auxiliary = {
            let histogram = build_histogram(raw_auxiliary);
            build_histogram_vec(&histogram)
        };
        let ciphertexts = {
            let histogram = build_histogram(raw_ciphertexts);
            build_histogram_vec(&histogram)
        };

        // If the sizes of these two datasets does not match, we do some random padding so that |C| = |M|.
        pad_auxiliary(&mut auxiliary, &ciphertexts);

        // Second, build the cost matrix.
        let n = auxiliary.len();
        let cost_matrix =
            Matrix::from_rows(self.build_cost_matrix(&auxiliary, &ciphertexts))
                .unwrap();

        // Invoke the Kuhn-Munkres algorithm to find the minimum matching.
        self.assignment = Some(kuhn_munkres_min(&cost_matrix).1);
        self.get_recovery_rate(correct, &auxiliary, &ciphertexts)
    }

    /// Given a correct mapping from plaintext to the ciphertext, calculate the accuracy of the attack.
    fn get_recovery_rate(
        &self,
        correct: &HashMap<T, Vec<u8>>,
        auxiliary: &Vec<HistType<T>>,
        ciphertexts: &Vec<HistType<Vec<u8>>>,
    ) -> f64 {
        // The number of messages correctly recovered.
        let mut sum = 0usize;
        // Calculate the total number of ciphertexts.
        let ciphertext_num = ciphertexts.iter().map(|e| e.1).sum::<usize>();

        for (i, j) in self.assignment.as_ref().unwrap().iter().enumerate() {
            // assignment[i] = j ==> The i-th message is assigned to j-th ciphertext.
            let message = &auxiliary.get(i).unwrap().0;
            let (ciphertext, count) = &ciphertexts.get(*j).unwrap();

            if let Some(value) = correct.get(message) {
                if value == ciphertext {
                    sum += count;
                }
            }
        }

        // Weighted rate.
        sum as f64 / ciphertext_num as f64
    }

    /// Construct the cost matrix for the histograms of the auxiliary dataset as well as the ciphertexts.
    ///
    /// As long as p < 1, this optimization problem can be for-mulated as a LSAP with cost matrix such that
    /// ```tex
    /// C_{ij} = || v_i - w_j ||_{p}.
    /// ```
    fn build_cost_matrix(
        &self,
        auxiliary: &Vec<HistType<T>>,
        ciphertexts: &Vec<HistType<Vec<u8>>>,
    ) -> Vec<Vec<i64>> {
        let mut cost_matrix = Vec::new();

        // Check if the histogram sizes match with each other.
        if auxiliary.len() != ciphertexts.len() {
            println!("[-] Sorry, the length does not match. Please pad auxiliary dataset first or check if auxiliary.len() > ciphertext.len().");
            return cost_matrix;
        }

        let n = auxiliary.len();
        for i in 0..n {
            let mut cur = Vec::new();
            for j in 0..n {
                let lhs = auxiliary.get(i).unwrap().1 as i64;
                let rhs = ciphertexts.get(j).unwrap().1 as i64;

                cur.push((lhs - rhs).pow(self.p as u32));
            }

            cost_matrix.push(cur);
        }

        cost_matrix
    }
}

/// This struct mainly implements the MLE-based attacker that aims to recover the one-to-many mapping
/// from the message to a set of ciphertexts obtained by the frequency smoothing scheme.
#[derive(Debug)]
pub struct MLEAttacker<T>
where
    T: Eq + Clone + Hash,
{
    /// The assignment of the attacker.
    assignment: Option<Vec<(usize, Vec<u8>)>>,
    /// A marker.
    _marker: PhantomData<T>,
}

impl<T> MLEAttacker<T>
where
    T: Eq + Clone + Hash,
{
    pub fn new() -> Self {
        Self {
            assignment: None,
            _marker: PhantomData,
        }
    }
}
