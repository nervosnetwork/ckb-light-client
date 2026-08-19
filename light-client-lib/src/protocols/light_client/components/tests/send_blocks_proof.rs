use ckb_types::{core::BlockBuilder, packed, prelude::*};

use super::super::send_blocks_proof::{verify_extra_hash, verify_legacy_extra_hash};

fn extension_bytes(byte: u8) -> packed::Bytes {
    packed::Bytes::new_builder().push(byte).build()
}

#[test]
fn verify_legacy_extra_hash_accepts_blocks_without_extension() {
    let block = BlockBuilder::default().build();
    assert!(verify_legacy_extra_hash(&[block.header()]).is_ok());
}

#[test]
fn verify_legacy_extra_hash_rejects_blocks_with_extension() {
    let block = BlockBuilder::default()
        .build()
        .as_advanced_builder()
        .extension(Some(extension_bytes(1)))
        .build();
    assert!(verify_legacy_extra_hash(&[block.header()]).is_err());
}

#[test]
fn verify_extra_hash_accepts_matching_extension() {
    let extension = extension_bytes(1);
    let block = BlockBuilder::default()
        .build()
        .as_advanced_builder()
        .extension(Some(extension.clone()))
        .build();
    let header = block.header();
    assert!(verify_extra_hash(&[header], &[packed::Byte32::zero()], &[Some(extension)]).is_ok());
}

#[test]
fn verify_extra_hash_rejects_mismatched_extension() {
    let block = BlockBuilder::default()
        .build()
        .as_advanced_builder()
        .extension(Some(extension_bytes(1)))
        .build();
    let header = block.header();
    assert!(verify_extra_hash(
        &[header],
        &[packed::Byte32::zero()],
        &[Some(extension_bytes(2))],
    )
    .is_err());
}
