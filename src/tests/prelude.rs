macro_rules! epoch {
    ($number:expr, $index:expr, $length:expr) => {
        ckb_types::core::EpochNumberWithFraction::new($number, $index, $length)
    };
    ($tuple:ident) => {{
        let (number, index, length) = $tuple;
        ckb_types::core::EpochNumberWithFraction::new(number, index, length)
    }};
}
