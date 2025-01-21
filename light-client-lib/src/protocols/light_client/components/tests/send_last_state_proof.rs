use ckb_constant::consensus::TAU;
use ckb_types::{
    utilities::difficulty_to_compact,
    {u256, U256},
};

use super::super::send_last_state_proof::{
    verify_tau, verify_total_difficulty, EpochDifficultyTrend, EstimatedLimit,
};

#[test]
fn test_calculate_tau_exponent() {
    let tau = 2;
    let limit_min = 2;
    let tau_u256 = U256::from(tau);
    let testcases = [
        // Unchanged & Increased / Decreased a few
        (u256!("0x100"), u256!("0x7f"), 1),
        (u256!("0x100"), u256!("0x80"), 0),
        (u256!("0x100"), u256!("0xff"), 0),
        (u256!("0x100"), u256!("0x100"), 0),
        (u256!("0x100"), u256!("0x101"), 0),
        (u256!("0x100"), u256!("0x200"), 0),
        (u256!("0x100"), u256!("0x201"), 1),
        // Increased a lot
        (u256!("0xff"), u256!("0x1000"), 4),
        (u256!("0x100"), u256!("0xfff"), 3),
        (u256!("0x100"), u256!("0x1000"), 3),
        (u256!("0x100"), u256!("0x1001"), 4),
        (u256!("0x101"), u256!("0x1000"), 3),
        // Decreased a lot
        (u256!("0x1000"), u256!("0xff"), 4),
        (u256!("0xfff"), u256!("0x100"), 3),
        (u256!("0x1000"), u256!("0x100"), 3),
        (u256!("0x1001"), u256!("0x100"), 3),
        (u256!("0x1000"), u256!("0x101"), 3),
    ];
    for (diff_start, diff_end, k) in testcases {
        let trend = EpochDifficultyTrend::new(&diff_start, &diff_end);
        for limit in limit_min..=(limit_min + k + 5) {
            let actual = trend.calculate_tau_exponent(tau, limit);
            let expected = if k == 0 || limit > k { Some(k) } else { None };
            assert_eq!(
                actual, expected,
                "{:#x} -> {:#x} (limit: {}, tau: {}) expect {:?} but got {:?}",
                diff_start, diff_end, limit, tau, expected, actual
            );
        }
        let diff_end_scope = {
            let mut tmp = diff_start.clone();
            match trend {
                EpochDifficultyTrend::Unchanged => (diff_end == tmp, tmp.clone(), tmp),
                EpochDifficultyTrend::Increased { .. } => {
                    for _ in 0..k {
                        tmp = tmp.saturating_mul(&tau_u256);
                    }
                    let diff_end_lt = tmp.clone();
                    let diff_end_ge = tmp.saturating_mul(&tau_u256);
                    let in_scope = diff_end_lt < diff_end && diff_end <= diff_end_ge;
                    (in_scope, diff_end_lt, diff_end_ge)
                }
                EpochDifficultyTrend::Decreased { .. } => {
                    for _ in 0..k {
                        tmp /= tau;
                    }
                    let diff_end_gt = tmp.clone();
                    let diff_end_le = tmp / tau;
                    let in_scope = diff_end_gt > diff_end && diff_end >= diff_end_le;
                    (in_scope, diff_end_gt, diff_end_le)
                }
            }
        };
        assert!(
            diff_end_scope.0,
            "{:#x} -> {:#x} got a incorrect scope ({:#x}, {:#x}]",
            diff_start, diff_end, diff_end_scope.1, diff_end_scope.2,
        );
    }
}

#[test]
fn test_split_epochs() {
    let tau = 2;
    let testcases = [
        // Unchanged
        (u256!("0x100"), u256!("0x100")),
        // Increased
        (u256!("0x100"), u256!("0x1000")),
        // Decreased
        (u256!("0x1000"), u256!("0x100")),
    ];
    for (diff_start, diff_end) in testcases {
        let trend = EpochDifficultyTrend::new(&diff_start, &diff_end);
        let k = trend.calculate_tau_exponent(tau, u64::MAX).unwrap();
        let n_min = if k < 2 { 2 } else { k + 1 };
        for n in n_min..=(n_min + 10) {
            for limit in [EstimatedLimit::Min, EstimatedLimit::Max] {
                let details = trend.split_epochs(limit, n, k);
                let total_epochs_count = details.total_epochs_count();
                assert_eq!(
                    total_epochs_count, n,
                    "{:#x} -> {:#x} (n: {}, k: {}, {:?}) \
                    total epochs count should be `n` but got {}",
                    diff_start, diff_end, n, k, limit, total_epochs_count,
                );
                let start_epochs_count = details.start.epochs_count();
                let end_epochs_count = details.end.epochs_count();
                let check_counts = {
                    let remainder = (n - k) % 2;
                    match trend {
                        EpochDifficultyTrend::Unchanged => {
                            start_epochs_count == end_epochs_count + remainder
                        }
                        EpochDifficultyTrend::Increased { .. } => match limit {
                            EstimatedLimit::Min => {
                                start_epochs_count + k == end_epochs_count + remainder
                            }
                            EstimatedLimit::Max => {
                                start_epochs_count == end_epochs_count + k + remainder
                            }
                        },
                        EpochDifficultyTrend::Decreased { .. } => match limit {
                            EstimatedLimit::Min => {
                                start_epochs_count == end_epochs_count + k + remainder
                            }
                            EstimatedLimit::Max => {
                                start_epochs_count + k == end_epochs_count + remainder
                            }
                        },
                    }
                };
                assert!(
                    check_counts,
                    "{:#x} -> {:#x} (n: {}, k: {}, {:?}) \
                    epochs count (start: {}, end: {}) is incorrect",
                    diff_start, diff_end, n, k, limit, start_epochs_count, end_epochs_count,
                );
                let total_epochs_count_without_last_epoch =
                    details.clone().remove_last_epoch().total_epochs_count();
                assert_eq!(
                    total_epochs_count_without_last_epoch,
                    n - 1,
                    "{:#x} -> {:#x} (n: {}, k: {}, {:?}) \
                    total epochs count without last epoch should be `n-1` but got {}",
                    diff_start,
                    diff_end,
                    n,
                    k,
                    limit,
                    total_epochs_count_without_last_epoch,
                );
            }
        }
    }
}

#[test]
fn test_check_total_difficulty_limit() {
    let tau = 2;
    let testcases = [
        // Unchanged
        (u256!("0x100"), u256!("0x100")),
        // Increased
        (u256!("0x100"), u256!("0x1000")),
        // Decreased
        (u256!("0x1000"), u256!("0x100")),
    ];
    for (diff_start, diff_end) in testcases {
        let trend = EpochDifficultyTrend::new(&diff_start, &diff_end);
        let k = trend.calculate_tau_exponent(tau, u64::MAX).unwrap();
        let n_min = if k < 2 { 2 } else { k + 1 };
        for n in n_min..=(n_min + 10) {
            for limit in [EstimatedLimit::Min, EstimatedLimit::Max] {
                let details = trend.split_epochs(limit, n, k).remove_last_epoch();
                let unaligned = U256::zero();
                let actual = trend.check_total_difficulty_limit(
                    limit,
                    n,
                    k,
                    &diff_end,
                    &diff_start,
                    tau,
                    &unaligned,
                );
                let expected = {
                    let start_epochs_count = details.start.epochs_count();
                    let end_epochs_count = details.end.epochs_count();
                    let mut curr = diff_start.clone();
                    let mut total = U256::zero();
                    match limit {
                        EstimatedLimit::Min => {
                            for _ in 0..start_epochs_count {
                                curr /= tau;
                                total += &curr;
                            }
                            for _ in 0..end_epochs_count {
                                curr *= tau;
                                total += &curr;
                            }
                            diff_end >= total
                        }
                        EstimatedLimit::Max => {
                            for _ in 0..start_epochs_count {
                                curr *= tau;
                                total += &curr;
                            }
                            for _ in 0..end_epochs_count {
                                curr /= tau;
                                total += &curr;
                            }
                            diff_end <= total
                        }
                    }
                };
                assert_eq!(
                    actual.is_ok(),
                    expected,
                    "{diff_start:#x} -> {diff_end:#x} (tau: {tau}, n: {n}, k: {k}, {limit:?}) \
                    total difficulty expect {} but got {} since {}",
                    expected,
                    actual.is_ok(),
                    actual.unwrap_err(),
                );
            }
        }
    }
}

#[test]
fn test_verify_tau() {
    let tau = TAU;
    let testcases = [
        (
            ((10, 0, 10), u256!("0x3f")),
            ((10, 9, 10), u256!("0x40")),
            Err(()),
        ),
        (
            ((10, 0, 10), u256!("0x40")),
            ((10, 9, 10), u256!("0x40")),
            Ok(true),
        ),
        (
            ((10, 0, 10), u256!("0x40")),
            ((10, 9, 10), u256!("0x41")),
            Err(()),
        ),
        (
            ((10, 0, 10), u256!("0x40")),
            ((15, 0, 10), u256!("0x1")),
            Ok(false),
        ),
        (
            ((10, 0, 10), u256!("0x40")),
            ((15, 0, 10), u256!("0x2")),
            Ok(true),
        ),
        (
            ((10, 0, 10), u256!("0x40")),
            ((15, 0, 10), u256!("0x3")),
            Ok(true),
        ),
        (
            ((10, 0, 10), u256!("0x40")),
            ((15, 0, 10), u256!("0x7ff")),
            Ok(true),
        ),
        (
            ((10, 0, 10), u256!("0x40")),
            ((15, 0, 10), u256!("0x800")),
            Ok(true),
        ),
        (
            ((10, 0, 10), u256!("0x40")),
            ((15, 0, 10), u256!("0x801")),
            Ok(false),
        ),
    ];
    for (start_data, end_data, expected_result) in testcases {
        let (start_epoch_data, start_block_difficulty) = start_data;
        let start_epoch = epoch!(start_epoch_data);
        let start_compact_target = difficulty_to_compact(start_block_difficulty.clone());
        let (end_epoch_data, end_block_difficulty) = end_data;
        let end_epoch = epoch!(end_epoch_data);
        let end_compact_target = difficulty_to_compact(end_block_difficulty.clone());
        let actual_result = verify_tau(
            start_epoch,
            start_compact_target,
            end_epoch,
            end_compact_target,
            tau,
        );
        match (expected_result, actual_result) {
            (Ok(expected), Ok(actual)) => {
                assert_eq!(
                    expected,
                    actual,
                    "verify tau expect {} but got {} \
                    when epoch: {:#}->{:#}, block-diff: {:#x}->{:#x}",
                    expected,
                    actual,
                    start_epoch,
                    end_epoch,
                    start_block_difficulty,
                    end_block_difficulty,
                );
            }
            (Err(_), Ok(actual)) => {
                panic!(
                    "verify tau expect an error but got {} \
                    when epoch: {:#}->{:#}, block-diff: {:#x}->{:#x}",
                    actual, start_epoch, end_epoch, start_block_difficulty, end_block_difficulty,
                );
            }
            (Ok(expected), Err(status)) => {
                panic!(
                    "verify tau expect {} but got {} \
                    when epoch: {:#}->{:#}, block-diff: {:#x}->{:#x}",
                    expected,
                    status,
                    start_epoch,
                    end_epoch,
                    start_block_difficulty,
                    end_block_difficulty,
                );
            }
            (Err(_), Err(_)) => {}
        }
    }
}

#[test]
fn test_verify_total_difficulty_in_same_epoch() {
    let tau = TAU;
    let block_difficulty = U256::from(4u32);
    let compact_target = difficulty_to_compact(block_difficulty.clone());
    let testcases = [
        (
            ((10, 0, 10), u256!("0x100")),
            ((10, 0, 10), u256!("0x100")),
            true,
        ),
        (
            ((10, 0, 10), u256!("0x100")),
            ((10, 1, 10), u256!("0x100")),
            false,
        ),
        (
            ((10, 0, 10), u256!("0x100")),
            ((10, 1, 10), u256!("0x103")),
            false,
        ),
        (
            ((10, 0, 10), u256!("0x100")),
            ((10, 1, 10), u256!("0x104")),
            true,
        ),
        (
            ((10, 0, 10), u256!("0x100")),
            ((10, 1, 10), u256!("0x105")),
            false,
        ),
    ];
    for (start_data, end_data, expected_result) in testcases {
        let (start_epoch_data, start_total_difficulty) = start_data;
        let start_epoch = epoch!(start_epoch_data);
        let (end_epoch_data, end_total_difficulty) = end_data;
        let end_epoch = epoch!(end_epoch_data);
        let result = verify_total_difficulty(
            start_epoch,
            compact_target,
            &start_total_difficulty,
            end_epoch,
            compact_target,
            &end_total_difficulty,
            tau,
        );
        if expected_result {
            assert!(
                result.is_ok(),
                "should be passed but failed when verified total difficulty when \
                epoch: {:#}->{:#}, block-diff: {:#x}, total-diff: {:#x}->{:#x} \
                since {}",
                start_epoch,
                end_epoch,
                block_difficulty,
                start_total_difficulty,
                end_total_difficulty,
                result.unwrap_err(),
            );
        }
        let end_total_difficulty_vec = if expected_result {
            vec![
                &end_total_difficulty - U256::from(3u32),
                &end_total_difficulty - U256::from(2u32),
                &end_total_difficulty - U256::from(1u32),
                &end_total_difficulty + U256::from(1u32),
                &end_total_difficulty + U256::from(2u32),
                &end_total_difficulty + U256::from(3u32),
            ]
        } else {
            vec![end_total_difficulty]
        };
        for end_total_difficulty in end_total_difficulty_vec {
            let result = verify_total_difficulty(
                start_epoch,
                compact_target,
                &start_total_difficulty,
                end_epoch,
                compact_target,
                &end_total_difficulty,
                tau,
            );
            assert!(
                result.is_err(),
                "should be failed but passed when verified total difficulty when \
                epoch: {:#}->{:#}, block-diff: {:#x}, total-diff: {:#x}->{:#x}",
                start_epoch,
                end_epoch,
                block_difficulty,
                start_total_difficulty,
                end_total_difficulty,
            );
        }
    }
}

#[test]
fn test_verify_total_difficulty_during_two_epochs() {
    let tau = TAU;
    let testcases = [
        (
            ((10, 4, 10), u256!("0x4"), u256!("0x100")),
            ((11, 4, 10), u256!("0x1"), u256!("0x119")),
            false,
        ),
        (
            ((10, 4, 10), u256!("0x4"), u256!("0x100")),
            ((11, 4, 10), u256!("0x2"), u256!("0x11e")),
            true,
        ),
        (
            ((10, 4, 10), u256!("0x4"), u256!("0x100")),
            ((11, 4, 10), u256!("0x3"), u256!("0x123")),
            true,
        ),
        (
            ((10, 4, 10), u256!("0x4"), u256!("0x100")),
            ((11, 4, 10), u256!("0x4"), u256!("0x128")),
            true,
        ),
        (
            ((10, 4, 10), u256!("0x4"), u256!("0x100")),
            ((11, 4, 10), u256!("0x5"), u256!("0x12d")),
            true,
        ),
        (
            ((10, 4, 10), u256!("0x4"), u256!("0x100")),
            ((11, 4, 10), u256!("0x6"), u256!("0x132")),
            true,
        ),
        (
            ((10, 4, 10), u256!("0x4"), u256!("0x100")),
            ((11, 4, 10), u256!("0x7"), u256!("0x137")),
            true,
        ),
        (
            ((10, 4, 10), u256!("0x4"), u256!("0x100")),
            ((11, 4, 10), u256!("0x8"), u256!("0x13c")),
            true,
        ),
        (
            ((10, 4, 10), u256!("0x4"), u256!("0x100")),
            ((11, 4, 10), u256!("0x9"), u256!("0x141")),
            false,
        ),
    ];
    for (start_data, end_data, expected_result) in testcases {
        let (start_epoch_data, start_block_difficulty, start_total_difficulty) = start_data;
        let start_epoch = epoch!(start_epoch_data);
        let start_compact_target = difficulty_to_compact(start_block_difficulty.clone());
        let (end_epoch_data, end_block_difficulty, end_total_difficulty) = end_data;
        let end_epoch = epoch!(end_epoch_data);
        let end_compact_target = difficulty_to_compact(end_block_difficulty.clone());
        let result = verify_total_difficulty(
            start_epoch,
            start_compact_target,
            &start_total_difficulty,
            end_epoch,
            end_compact_target,
            &end_total_difficulty,
            tau,
        );
        if expected_result {
            assert!(
                result.is_ok(),
                "should be passed but failed when verified total difficulty when \
                epoch: {:#}->{:#}, block-diff: {:#x}->{:#x}, total-diff: {:#x}->{:#x} \
                since {}",
                start_epoch,
                end_epoch,
                start_block_difficulty,
                end_block_difficulty,
                start_total_difficulty,
                end_total_difficulty,
                result.unwrap_err(),
            );
        }
        let end_total_difficulty_vec = if expected_result {
            vec![
                &end_total_difficulty - U256::from(1u32),
                &end_total_difficulty + U256::from(1u32),
            ]
        } else {
            vec![end_total_difficulty]
        };
        for end_total_difficulty in end_total_difficulty_vec {
            let result = verify_total_difficulty(
                start_epoch,
                start_compact_target,
                &start_total_difficulty,
                end_epoch,
                end_compact_target,
                &end_total_difficulty,
                tau,
            );
            assert!(
                result.is_err(),
                "should be failed but passed when verified total difficulty when \
                epoch: {:#}->{:#}, block-diff: {:#x}->{:#x}, total-diff: {:#x}->{:#x}",
                start_epoch,
                end_epoch,
                start_block_difficulty,
                end_block_difficulty,
                start_total_difficulty,
                end_total_difficulty,
            );
        }
    }
}

#[test]
fn test_verify_total_difficulty_during_more_than_two_epochs() {
    let tau = TAU;
    let testcases = [
        // Epoch Difficulty (40 -> 40):
        // - min total difficulty: 40 -> 20 -> 10 -> 20 -> 40
        // - max total difficulty: 40 -> 80 -> 160 -> 80 -> 40
        (
            ((11, 0, 10), u256!("0x4"), u256!("0x100")),
            ((15, 0, 10), u256!("0x4"), u256!("0xff")),
            false,
        ),
        (
            ((11, 0, 10), u256!("0x4"), u256!("0x100")),
            ((15, 0, 10), u256!("0x4"), u256!("0x150")),
            false,
        ),
        (
            ((11, 0, 10), u256!("0x4"), u256!("0x100")),
            ((15, 0, 10), u256!("0x4"), u256!("0x15a")),
            true,
        ),
        (
            ((11, 0, 10), u256!("0x4"), u256!("0x100")),
            ((15, 0, 10), u256!("0x4"), u256!("0x1a0")),
            true,
        ),
        (
            ((11, 0, 10), u256!("0x4"), u256!("0x100")),
            ((15, 0, 10), u256!("0x4"), u256!("0x268")),
            true,
        ),
        (
            ((11, 0, 10), u256!("0x4"), u256!("0x100")),
            ((15, 0, 10), u256!("0x4"), u256!("0x269")),
            false,
        ),
    ];
    for (start_data, end_data, expected_result) in testcases {
        let (start_epoch_data, start_block_difficulty, start_total_difficulty) = start_data;
        let start_epoch = epoch!(start_epoch_data);
        let start_compact_target = difficulty_to_compact(start_block_difficulty.clone());
        let (end_epoch_data, end_block_difficulty, end_total_difficulty) = end_data;
        let end_epoch = epoch!(end_epoch_data);
        let end_compact_target = difficulty_to_compact(end_block_difficulty.clone());
        let result = verify_total_difficulty(
            start_epoch,
            start_compact_target,
            &start_total_difficulty,
            end_epoch,
            end_compact_target,
            &end_total_difficulty,
            tau,
        );
        if expected_result {
            assert!(
                result.is_ok(),
                "should be passed but failed when verified total difficulty when \
                epoch: {:#}->{:#}, block-diff: {:#x}->{:#x}, total-diff: {:#x}->{:#x} \
                since {}",
                start_epoch,
                end_epoch,
                start_block_difficulty,
                end_block_difficulty,
                start_total_difficulty,
                end_total_difficulty,
                result.unwrap_err(),
            );
        } else {
            assert!(
                result.is_err(),
                "should be failed but passed when verified total difficulty when \
                epoch: {:#}->{:#}, block-diff: {:#x}->{:#x}, total-diff: {:#x}->{:#x}",
                start_epoch,
                end_epoch,
                start_block_difficulty,
                end_block_difficulty,
                start_total_difficulty,
                end_total_difficulty,
            );
        }
    }
}
