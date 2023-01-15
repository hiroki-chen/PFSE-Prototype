//! This module mainly implements the inference-attack family. This contains the frequency analysis, l_p optimization as well as
//! the (scaled) MLE attack. This module should be enabled by the `attack` (optional) feature.

use std::{collections::HashMap, fmt::Debug, hash::Hash, marker::PhantomData};

use log::error;
use pathfinding::{
    kuhn_munkres::kuhn_munkres_min,
    prelude::{Matrix, Weights},
};
use serde::{Deserialize, Serialize};

use crate::{
    fse::{HistType, Random, ValueType},
    util::{build_histogram, build_histogram_vec, intersect, pad_auxiliary},
};

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum AttackType {
    LpOptimization,
    MleAttack,
}

/// An attacker that uses the $\ell_{p}$-norm to optimize the attack. The basic idea is find an as-signment from ciphertexts to
/// plaintexts that minimizes a given cost function, chosen here to be the $\ell_{p}$ distance between the histograms of the dataset.
#[derive(Debug)]
pub struct LpAttacker<T>
where
    T: Eq + Clone + Hash + Random + Debug,
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
    T: Eq + Clone + Hash + Random + Debug,
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
        correct: &HashMap<T, Vec<Vec<u8>>>,
        local_table: &HashMap<T, Vec<ValueType>>,
        raw_ciphertexts: &[Vec<u8>],
        ciphertext_weight: &HashMap<Vec<u8>, f64>,
    ) -> f64 {
        // First, build the histograms for the two datasets.
        // Generate auxiliary according to the local table.
        let mut auxiliary = Vec::new();
        for (message, information) in local_table.iter() {
            for &(_, size, count) in information.iter() {
                let weight = count as f64 / size as f64;
                auxiliary.push((message.clone(), weight, count));
            }
        }
        auxiliary.sort_by(|lhs, rhs| rhs.1.partial_cmp(&lhs.1).unwrap());

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
        self.get_recovery_rate(
            correct,
            &auxiliary,
            &ciphertexts,
            ciphertext_weight,
        )
    }

    /// Given a correct mapping from plaintext to the ciphertext, calculate the accuracy of the attack.
    fn get_recovery_rate(
        &self,
        correct: &HashMap<T, Vec<Vec<u8>>>,
        auxiliary: &[(T, f64, usize)],
        ciphertexts: &[HistType<Vec<u8>>],
        ciphertext_weight_map: &HashMap<Vec<u8>, f64>,
    ) -> f64 {
        let mut sum = 0f64;
        let message_num = auxiliary.iter().map(|e| e.2).sum::<usize>();

        for (i, j) in self.assignment.as_ref().unwrap().iter().enumerate() {
            // assignment[i] = j ==> The i-th message is assigned to j-th ciphertext.
            let (message, _, count) = &auxiliary.get(i).unwrap();
            let message_weight = *count as f64 / message_num as f64;
            let (ciphertext, count) = &ciphertexts.get(*j).unwrap();

            if let Some(value) = correct.get(message) {
                let ciphertext_weight =
                    ciphertext_weight_map.get(ciphertext).unwrap();
                sum += value.iter().filter(|&e| e == ciphertext).count() as f64
                    * ciphertext_weight
                    * message_weight;
            }
        }

        // Weighted rate.
        sum
    }

    /// Construct the cost matrix for the histograms of the auxiliary dataset as well as the ciphertexts.
    ///
    /// As long as p < 1, this optimization problem can be for-mulated as a LSAP with cost matrix such that
    /// ```tex
    /// C_{ij} = || v_i - w_j ||_{p}.
    /// ```
    fn build_cost_matrix(
        &self,
        auxiliary: &Vec<(T, f64, usize)>,
        ciphertexts: &Vec<HistType<Vec<u8>>>,
    ) -> Vec<Vec<i64>> {
        let mut cost_matrix = Vec::new();

        // Check if the histogram sizes match with each other.
        if auxiliary.len() != ciphertexts.len() {
            error!("Sorry, the length does not match. Please pad auxiliary dataset first or check if auxiliary.len() > ciphertext.len(). auxiliary.len() = {}, ciphertext.len() = {}", auxiliary.len(), ciphertexts.len());
            return cost_matrix;
        }

        let n = auxiliary.len();
        for i in 0..n {
            let mut cur = Vec::new();
            for j in 0..n {
                let lhs = auxiliary.get(i).unwrap().2 as i64;
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
///
/// # Example
/// ```rust
/// let mut attacker = MLEAttacker::<String>::new();
/// let auxiliary = vec![1, 2, 3]
///     .into_iter()
///     .map(|e| e.to_string())
///     .collect::<Vec<_>>();
/// let ciphertexts = auxiliary
///     .iter()
///     .copied()
///     .cycle()
///     .take(3 * 2)
///     .collect::<Vec<_>>();
/// let local_table = vec![
///         ("1".to_string(), (1, 1, 1)),
///         ("2".to_string(), (2, 2, 2)),
///         ("3".to_string(), (3, 3, 3)),
///     ]
///     .into_iter()
///     .collect::<HashMap<String, ValueType>>();
/// // Suppose you have construct some correct mapping called `correct`.
/// attacker.attack(&correct, &local_table, &auxiliary, &ciphertexts);
/// ```
#[derive(Debug)]
pub struct MLEAttacker<T>
where
    T: Eq + Clone + Hash + Debug,
{
    /// The assignment of the attacker.
    assignment: Option<Vec<(usize, Vec<Vec<u8>>)>>,
    /// A marker.
    _marker: PhantomData<T>,
}

impl<T> MLEAttacker<T>
where
    T: Eq + Clone + Hash + Debug,
{
    pub fn new() -> Self {
        Self {
            assignment: None,
            _marker: PhantomData,
        }
    }

    /// Perform the MLE attack. The attack proceeds as follows.
    /// 1. Sort the ciphertexts and auxiliary datasets so that each element is in descending order per frequency.
    ///    This step is automatically done by [`util::build_histogram_vec`].
    /// 2. Scale the auxiliary dataset because there are one-to-many mappings.
    /// 3. Suppose the attacker knows the size of ciphertext set of each message, it then assigns the most frequent
    ///    ciphertext to the most frequent (scaled) message according to the size of its ciphertext set.
    ///
    /// Note that we assume the attacker knows the exact size of the ciphertext set of each message; this is done
    /// by inputting the `local_table` obtained from the [`PFSEContext`] struct.
    pub fn attack(
        &mut self,
        correct: &HashMap<T, Vec<Vec<u8>>>,
        local_table: &HashMap<T, Vec<ValueType>>,
        raw_ciphertexts: &[Vec<u8>],
        ciphertext_weight: &HashMap<Vec<u8>, f64>,
    ) -> f64 {
        // Generate auxiliary according to the local table.
        let mut message_num = 0;
        // <message, set size, count>.
        let mut auxiliary = Vec::new();
        for (message, information) in local_table.iter() {
            for &(_, size, count) in information.iter() {
                auxiliary.push((message.clone(), size, count));
                message_num += count;
            }
        }
        auxiliary.sort_by(|lhs, rhs| {
            let l = lhs.2 as f64 / lhs.1 as f64;
            let r = rhs.2 as f64 / rhs.1 as f64;
            r.partial_cmp(&l).unwrap()
        });

        let ciphertexts = {
            let histogram = build_histogram(raw_ciphertexts);
            build_histogram_vec(&histogram)
        };

        // Do the assignment.
        let mut assignment = Vec::new();
        // The index for the message: which one are we accessing.
        let mut cur = 0usize;
        // The left boundary iterator for ciphertext set.
        let mut i = 0usize;
        while i < ciphertexts.len() {
            let current_size = auxiliary.get(cur).unwrap().1;
            let ciphertext_set = ciphertexts[i..i + current_size]
                .iter()
                .cloned()
                .map(|e| e.0)
                .collect::<Vec<_>>();

            assignment.push((cur, ciphertext_set));
            cur += 1;
            i += current_size;
        }

        self.assignment = Some(assignment);
        self.get_recovery_rate(
            message_num,
            correct,
            &auxiliary,
            &ciphertexts,
            ciphertext_weight,
        )
    }

    fn get_recovery_rate(
        &self,
        message_num: usize,
        correct: &HashMap<T, Vec<Vec<u8>>>,
        auxiliary: &[(T, usize, usize)],
        ciphertexts: &[HistType<Vec<u8>>],
        ciphertext_weight_map: &HashMap<Vec<u8>, f64>,
    ) -> f64 {
        let mut sum = 0f64;
        for (index, assignment) in self.assignment.as_ref().unwrap().iter() {
            let (current_message, _, count) = &auxiliary.get(*index).unwrap();
            let correct_ciphertexts = correct.get(current_message).unwrap();
            let common = intersect(assignment, correct_ciphertexts);

            // Find the weight of the message.
            let message_weight = *count as f64 / message_num as f64;
            // Find the weight of the ciphertexts.
            for correct_ciphertext in common.iter() {
                let ciphertext_weight =
                    ciphertext_weight_map.get(correct_ciphertext).unwrap();
                sum += message_weight * ciphertext_weight;
            }
        }

        sum
    }
}

impl<T> Default for MLEAttacker<T>
where
    T: Eq + Clone + Hash + Debug,
{
    fn default() -> Self {
        Self::new()
    }
}
