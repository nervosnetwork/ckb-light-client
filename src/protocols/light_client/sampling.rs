use std::collections::HashSet;

use ckb_types::{core::BlockNumber, U256};
use log::trace;
use numext_fixed_uint::{prelude::UintConvert as _, U512};
use rand::{thread_rng, Rng as _};

use crate::protocols::LAST_N_BLOCKS;

const C_FRACTION: f64 = 0.5;

// Since `log(2**32,10) = 9.63`.
const RATIO_SCALE_FACTOR: u32 = 1_000_000_000;

pub(crate) struct FlyClientPDF {
    x_max: f64,
    delta: f64,

    start_difficulty: U256,
    difficulty_range: U256,
    difficulty_boundary: U256,
}

// ### Warnings
//
// `ratio` should be less than 1.0.
pub(crate) fn multiply(uint: &U256, ratio: f64) -> U256 {
    let (uint_512, _): (U512, bool) = uint.convert_into();
    let numerator = (ratio * f64::from(RATIO_SCALE_FACTOR)) as u32;
    let denominator = RATIO_SCALE_FACTOR;
    let num_512 = (uint_512 * U512::from(numerator)) / U512::from(denominator);
    let (num, _): (U256, bool) = num_512.convert_into();
    if num.is_zero() {
        U256::one()
    } else {
        num
    }
}

impl FlyClientPDF {
    pub(crate) fn new(
        delta: f64,
        start_difficulty: U256,
        difficulty_range: U256,
        difficulty_boundary: U256,
    ) -> Self {
        let x_max = 1.0 - delta;
        Self {
            x_max,
            delta,
            start_difficulty,
            difficulty_range,
            difficulty_boundary,
        }
    }

    // Implementation for FlyClient PDF:
    //
    // - Inverse Transform Method
    //   - PDF: $$g(x) = \frac{1}{(x-1)\ln{\delta}}$$
    //   - CDF: $$F(x) = \frac{\ln{(1-x)}}{ln{\delta}}$$
    //   - Inverse Function of CDF: $$h(x) = F^{-1}(x) = 1 - \delta^{x}$$
    fn gen_x(&self) -> f64 {
        let mut rng = thread_rng();
        let x: f64 = rng.gen_range(0.0..self.x_max);
        1.0 - self.delta.powf(x)
    }

    fn random_sample(&self) -> U256 {
        let sample = &self.start_difficulty + multiply(&self.difficulty_range, self.gen_x());
        if sample >= self.difficulty_boundary {
            &self.difficulty_boundary - 1u32
        } else {
            sample
        }
    }

    pub(crate) fn sampling(&self, samples_count: BlockNumber) -> HashSet<U256> {
        let mut difficulties = HashSet::default();
        for _ in 0..samples_count {
            let difficulty = self.random_sample();
            difficulties.insert(difficulty);
        }
        difficulties
    }
}

// Include the start block, and exclude the last block.
pub(crate) fn sample_blocks(
    start_number: BlockNumber,
    start_difficulty: &U256,
    last_number: BlockNumber,
    last_difficulty: &U256,
) -> (U256, Vec<U256>) {
    let blocks_count = last_number - start_number;
    let k = estimate_k(LAST_N_BLOCKS, blocks_count, C_FRACTION);
    let samples_count = estimate_samples_count(blocks_count, LAST_N_BLOCKS, k);

    let delta = C_FRACTION.powf(k);
    let difficulty_range = last_difficulty - start_difficulty;
    let difficulty_boundary_added = multiply(&difficulty_range, 1.0 - delta);
    let difficulty_boundary = start_difficulty + &difficulty_boundary_added;

    trace!(
        "sampling: samples={}, delta={}, k={} in [{},{}), [{}, {}, {})",
        samples_count,
        delta,
        k,
        start_number,
        last_number,
        start_difficulty,
        difficulty_boundary,
        last_difficulty,
    );

    let pdf = FlyClientPDF::new(
        delta,
        start_difficulty.clone(),
        difficulty_range,
        difficulty_boundary.clone(),
    );
    let mut difficulties: Vec<_> = pdf.sampling(samples_count).into_iter().collect();
    difficulties.sort();
    (difficulty_boundary, difficulties)
}

// Estimate the $k$ to limit the length of the $\delta$ region (ref: section 5.4 in
// [FlyClient: Super-Light Clients for Cryptocurrencies]).
//
// - Let
//   - $l$ denote the expected length of the $\delta$ region.
//   - $n$ denote the length of the sampled region.
//   - $c$ denote the fraction of the adversary’s computing power relative to the honest computing power.
// - So
//   - $\delta = c^k$
//   - $l = n * \delta$
// - Then we can get
//   - $k = \log_{c}{\frac{l}{n}}$
//
// [FlyClient: Super-Light Clients for Cryptocurrencies]: https://eprint.iacr.org/2019/226.pdf
pub(crate) fn estimate_k(l: BlockNumber, n: BlockNumber, c: f64) -> f64 {
    ((l as f64) / (n as f64)).log(c)
}

// Estimate the samples count (ref: lemma 2 in section 5.3 of [FlyClient: Super-Light Clients for Cryptocurrencies]).
//
// [FlyClient: Super-Light Clients for Cryptocurrencies]: https://eprint.iacr.org/2019/226.pdf
pub(crate) fn estimate_samples_count(
    blocks_count: BlockNumber,
    last_n_blocks: BlockNumber,
    k: f64,
) -> BlockNumber {
    if blocks_count <= last_n_blocks {
        trace!(
            "sampling: no sampled blocks since the blocks count ({}<={}) is too small",
            blocks_count,
            last_n_blocks
        );
        0
    } else {
        (k * (blocks_count as f64).log10()) as BlockNumber
    }
}
