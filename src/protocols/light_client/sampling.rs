use std::collections::HashSet;

use ckb_types::{
    core::{BlockNumber, RationalU256},
    U256,
};
use log::trace;
use rand::{thread_rng, Rng as _};

use crate::protocols::LAST_N_BLOCKS;

const C_FRACTION: f64 = 0.5;
const K_DELTA: f64 = 10.0;

const K_SAMPLES: f64 = 2.0;
const DIFFICULTY_SCALE_FACTOR: u32 = 1024;

const RATIO_SCALE_FACTOR: u32 = 1_000_000_000;

struct FlyClientPDF {
    x_max: f64,
    delta: f64,

    start_difficulty: U256,
    difficulty_range: U256,
    difficulty_boundary: U256,
}

fn multiply(uint: &U256, ratio: f64) -> U256 {
    let numerator = (ratio * f64::from(RATIO_SCALE_FACTOR)) as u32;
    let denominator = RATIO_SCALE_FACTOR;
    let rational = RationalU256::new(U256::from(numerator), U256::from(denominator));

    let num = (RationalU256::from_u256(uint.to_owned()) * rational).into_u256();
    if num.is_zero() {
        U256::one()
    } else {
        num
    }
}

impl FlyClientPDF {
    fn new(
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

    fn sampling(&self, samples_count: BlockNumber) -> HashSet<U256> {
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
    let mut samples_count = if blocks_count <= LAST_N_BLOCKS {
        trace!(
            "sampling: no sampled blocks since the blocks count ({}<={}) is too small",
            blocks_count,
            LAST_N_BLOCKS
        );
        0
    } else {
        ((blocks_count as f64).log2() * K_SAMPLES) as BlockNumber
    };

    let delta = C_FRACTION.powf(K_DELTA);
    let difficulty_range = last_difficulty - start_difficulty;
    let difficulty_boundary_added = multiply(&difficulty_range, 1.0 - delta);
    let difficulty_boundary = start_difficulty + &difficulty_boundary_added;
    while difficulty_boundary_added <= U256::from(samples_count) * DIFFICULTY_SCALE_FACTOR {
        samples_count /= 2;
    }

    trace!(
        "sampling: samples={}, delta={} in [{},{}), [{}, {}, {})",
        samples_count,
        delta,
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
