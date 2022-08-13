use ckb_types::{u256, U256};

use super::super::send_block_samples::{EpochDifficultyTrend, EstimatedLimit};

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
fn test_calculate_total_difficulty_limit() {
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
                let actual = trend.calculate_total_difficulty_limit(&diff_start, tau, &details);
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
                        }
                    }
                    total
                };
                assert_eq!(
                    actual, expected,
                    "{:#x} -> {:#x} (tau: {}, n: {}, k: {}, {:?}) \
                    total difficulty expect {:#x} but got {:#x}",
                    diff_start, diff_end, tau, n, k, limit, expected, actual,
                );
            }
        }
    }
}
