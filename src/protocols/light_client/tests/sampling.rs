use ckb_types::{u256, U256};

use super::super::sampling::{
    estimate_k, estimate_samples_count, multiply, sample_blocks, FlyClientPDF,
};

#[test]
fn test_multiply() {
    let u256_max = u256!("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    let testcases = [
        ((u256_max.clone(), 1.0 / 2.0), (&u256_max) / 2u32),
        ((u256_max.clone(), 1.0 / 4.0), (&u256_max) / 4u32),
        ((u256_max.clone(), 1.0 / 8.0), (&u256_max) / 8u32),
        ((u256_max.clone(), 1.0 / 16.0), (&u256_max) / 16u32),
        ((u256_max.clone(), 1.0 / 32.0), (&u256_max) / 32u32),
        ((u256_max.clone(), 1.0 / 64.0), (&u256_max) / 64u32),
        ((u256_max.clone(), 1.0 / 128.0), (&u256_max) / 128u32),
        ((u256_max.clone(), 1.0 / 256.0), (&u256_max) / 256u32),
        ((u256_max.clone(), 1.0 / 512.0), (&u256_max) / 512u32),
        (
            (u256_max.clone(), 0.333333333), // 1/3
            u256!("0x55555553e6d4575218c8f1177c3fe3e813c77f7d5b16f45aa7b8b89021423c5c"),
        ),
        (
            (u256_max.clone(), 0.047619047), // 1/(3*7)
            u256!("0xc30c309881ca22ac0509b2b9d9b398a6de035e8cdbcea5f377b9fe71931ddd1"),
        ),
        (
            (u256_max.clone(), 0.000001031), // 1/(3*7*11*13*17*19)
            u256!("0x114c1c7cfd1a8c371f3fd0136d0906a8aa7273a9b4b395321a9e2abcb0e4"),
        ),
        (
            (u256_max.clone(), 0.000000045), // 1/(3*7*11*13*17*19*23)
            u256!("0xc14605f3b4ee08dc9d7a4ed09d91cbc4e4f6e524318d96abfe76122afa"),
        ),
        ((u256_max, 0.0), u256!("0x1")),
        ((u256!("0x0"), 0.9), u256!("0x1")),
    ];
    for ((uint, ratio), expected) in testcases {
        let actual = multiply(&uint, ratio);
        assert_eq!(
            expected, actual,
            "multiply {:#x} by {:.9} expect {:#x} but got {:#x}",
            uint, ratio, expected, actual,
        );
    }
}

#[test]
fn test_estimate_samples_count_when_blocks_count_le_last_n_blocks() {
    for last_n_blocks in 1..100 {
        for blocks_count in 1..=last_n_blocks {
            let samples_count = estimate_samples_count(blocks_count, last_n_blocks, 1.0, 50);
            assert_eq!(
                samples_count, 0,
                "samples count should be zero when \
                blocks_count = {} and last_n_blocks = {}",
                blocks_count, last_n_blocks,
            );
        }
    }
}

#[test]
fn test_estimate_k_and_samples_count() {
    let lambda = 50;
    let testcases = [
        // l = 100, c = 0.5
        (
            (100, 0.5),
            vec![
                (1_000, (3.322, 0)),
                (10_000, (6.644, 113)),
                (100_000, (9.966, 228)),
                (1_000_000, (13.288, 343)),
                (2_000_000, (14.288, 378)),
                (4_000_000, (15.288, 413)),
                (6_000_000, (15.873, 433)),
                (8_000_000, (16.288, 447)),
                (10_000_000, (16.610, 459)),
                (100_000_000, (19.932, 574)),
                (1_000_000_000, (23.253, 689)),
            ],
        ),
        // l = 500, c = 0.5
        (
            (500, 0.5),
            vec![
                (1_000, (1.000, 0)),
                (10_000, (4.322, 0)),
                (100_000, (7.644, 0)),
                (1_000_000, (10.966, 0)),
                (10_000_000, (14.288, 0)),
                (100_000_000, (17.610, 93)),
                (1_000_000_000, (20.932, 208)),
            ],
        ),
        // l = 100, c = 0.9
        (
            (100, 0.9),
            vec![
                (1_000, (21.854, 640)),
                (10_000, (43.709, 1398)),
                (100_000, (65.563, 2155)),
                (1_000_000, (87.417, 2913)),
                (10_000_000, (109.272, 3670)),
                (100_000_000, (131.126, 4428)),
                (1_000_000_000, (152.980, 5185)),
            ],
        ),
    ];
    for ((l, c), n_and_expected) in testcases {
        for (n, (k_expected, sc_expected)) in n_and_expected {
            let k_actual = estimate_k(l, n, c);
            let k_difference = k_expected - k_actual;
            let k_is_same = k_difference.abs() < 0.001;
            assert!(
                k_is_same,
                "estimate k, expect {:.3} but got {:.3} (l: {}, n: {}, c:{}, lambda: {})",
                k_expected, k_actual, l, n, c, lambda
            );
            let sc_actual = estimate_samples_count(n, l, k_actual, lambda);
            assert_eq!(
                sc_expected, sc_actual,
                "estimate samples count, expect {} but got {} (l: {}, n: {}, c:{}, lambda: {})",
                sc_expected, sc_actual, l, n, c, lambda
            );
        }
    }
}

#[test]
fn test_fly_client_pdf_samples_should_be_smaller_than_the_boundary() {
    let delta = 0.1;
    let start_difficulty = u256!("0x0");
    let difficulty_range = u256!("0x1000");
    let difficulty_boundary = u256!("0x5");
    let pdf = FlyClientPDF::new(
        delta,
        start_difficulty,
        difficulty_range,
        difficulty_boundary.clone(),
    );
    for sample in pdf.sampling(100) {
        assert!(
            sample < difficulty_boundary,
            "sample ({:#x}) should always be smaller than boundary ({:#x})",
            sample,
            difficulty_boundary
        );
    }
}

#[test]
fn test_sample_blocks() {
    let last_n_blocks = 100;
    let testcases = [
        (
            (1000, u256!("0x10000"), 1010, u256!("0x10100")),
            (u256!("0x10001"), 0),
        ),
        (
            (1000, u256!("0x10000"), 2000, u256!("0x20000")),
            (u256!("0x1e666"), 0),
        ),
        (
            (1000, u256!("0x10000"), 5000, u256!("0x50000")),
            (u256!("0x4e666"), 67),
        ),
        (
            (1000, u256!("0x10000"), 10000, u256!("0x100000")),
            (u256!("0xfd555"), 108),
        ),
    ];
    for (inputs, expected) in testcases {
        let (start_number, start_difficulty, last_number, last_difficulty) = inputs;
        let (expected_difficulty_boundary, expected_difficulties_len) = expected;
        let mut is_passed = false;
        let mut max = 0;
        for _ in 0..10 {
            let (difficulty_boundary, difficulties) = sample_blocks(
                start_number,
                &start_difficulty,
                last_number,
                &last_difficulty,
                last_n_blocks,
            );
            assert_eq!(
                difficulty_boundary,
                expected_difficulty_boundary,
                "difficulty boundary expect {:#x} but got {:#x} \
                when number {} -> {}, difficulty {:#x} -> {:#x}",
                expected_difficulty_boundary,
                difficulty_boundary,
                start_number,
                last_number,
                start_difficulty,
                last_difficulty
            );
            if difficulties.len() > expected_difficulties_len {
                panic!(
                    "size of difficulties should NOT greater than {} but got {} \
                    when number {} -> {}, difficulty {:#x} -> {:#x}",
                    expected_difficulties_len,
                    difficulties.len(),
                    start_number,
                    last_number,
                    start_difficulty,
                    last_difficulty
                );
            } else if difficulties.len() == expected_difficulties_len {
                is_passed = true;
                break;
            } else if difficulties.len() > max {
                max = difficulties.len();
            }
        }
        assert!(
            is_passed,
            "size of difficulties should be {} in most cases \
            when number {} -> {}, difficulty {:#x} -> {:#x} but got {}",
            expected_difficulties_len,
            start_number,
            last_number,
            start_difficulty,
            last_difficulty,
            max,
        );
    }
}
