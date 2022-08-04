use super::super::sampling::{estimate_k, estimate_samples_count};

#[test]
fn test_estimate_k_and_samples_count() {
    let testcases = [
        // l = 100, c = 0.5
        (
            (100, 0.5),
            vec![
                (1_000, (3.322, 9)),
                (10_000, (6.644, 26)),
                (100_000, (9.966, 49)),
                (1_000_000, (13.288, 79)),
                (2_000_000, (14.288, 90)),
                (4_000_000, (15.288, 100)),
                (6_000_000, (15.873, 107)),
                (8_000_000, (16.288, 112)),
                (10_000_000, (16.610, 116)),
                (100_000_000, (19.932, 159)),
                (1_000_000_000, (23.253, 209)),
            ],
        ),
        // l = 500, c = 0.5
        (
            (500, 0.5),
            vec![
                (1_000, (1.000, 3)),
                (10_000, (4.322, 17)),
                (100_000, (7.644, 38)),
                (1_000_000, (10.966, 65)),
                (10_000_000, (14.288, 100)),
                (100_000_000, (17.610, 140)),
                (1_000_000_000, (20.932, 188)),
            ],
        ),
        // l = 100, c = 0.9
        (
            (100, 0.9),
            vec![
                (1_000, (21.854, 65)),
                (10_000, (43.709, 174)),
                (100_000, (65.563, 327)),
                (1_000_000, (87.417, 524)),
                (10_000_000, (109.272, 764)),
                (100_000_000, (131.126, 1049)),
                (1_000_000_000, (152.980, 1376)),
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
                "estimate k, expect {:.3} but got {:.3} (l: {}, n: {}, c:{})",
                k_expected, k_actual, l, n, c,
            );
            let sc_actual = estimate_samples_count(n, l, k_actual);
            assert_eq!(
                sc_expected, sc_actual,
                "estimate samples count, expect {} but got {} (l: {}, n: {}, c:{})",
                sc_expected, sc_actual, l, n, c,
            );
        }
    }
}
