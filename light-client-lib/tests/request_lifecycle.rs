//! Real proof processors over an explicitly trusted DummyPoW fixture anchor.
//! These tests cover request ownership, not canonical membership or fresh reproof.
#![cfg(not(target_arch = "wasm32"))]
pub use ckb_light_client_lib::{protocols, service, storage};
use ckb_types::{packed, prelude::*};

#[allow(dead_code)]
#[path = "../src/tests/utils/network_context.rs"]
mod network_context;
use network_context::MockNetworkContext;

#[path = "support/request_fixture.rs"]
mod request_fixture;
use request_fixture::{Fixture, KINDS};

#[tokio::test]
async fn matching_positive_and_negative_replies_complete_the_owned_slot() {
    for kind in KINDS {
        for negative in [false, true] {
            let mut f = Fixture::new();
            let hash = f.hash(kind);
            f.arm(kind, &hash).await;
            let reply = if negative {
                f.negative(kind, f.wire.clone(), vec![hash.clone()])
            } else {
                f.positive(kind, f.wire.clone(), false)
            };
            f.receive(reply).await;
            if negative {
                assert!(f.fetch(kind, &hash) == "missing");
            } else {
                assert!(f.present(kind));
            }
            f.arm(kind, &packed::Byte32::new([31; 32])).await;
            assert!(f.context.not_banned(f.peer));
        }
    }
}

#[tokio::test]
async fn matching_invalid_proof_is_retryable_and_a_valid_retry_completes() {
    for kind in KINDS {
        let mut f = Fixture::new();
        let hash = f.hash(kind);
        f.arm(kind, &hash).await;
        f.receive(f.positive(kind, f.wire.clone(), true)).await;
        assert!(!f.present(kind));
        f.tick().await;
        assert!(
            !f.context.sent_messages().borrow().is_empty(),
            "invalid {kind:?} proof stranded its fetch"
        );
        f.receive(f.positive(kind, f.wire.clone(), false)).await;
        assert!(f.present(kind));
        assert!(f.context.not_banned(f.peer));
    }
}

#[tokio::test]
async fn stale_positive_and_negative_replies_do_not_retire_a_replacement_slot() {
    for kind in KINDS {
        for negative in [false, true] {
            let mut f = Fixture::new();
            let current = packed::Byte32::new([31; 32]);
            f.arm(kind, &current).await;
            let old = if negative {
                f.negative(kind, f.wire.clone(), vec![f.hash(kind)])
            } else {
                f.positive(kind, f.wire.clone(), false)
            };
            f.receive(old).await;
            assert!(
                !f.present(kind),
                "old reply was persisted for an unrelated operation"
            );
            f.receive(f.negative(kind, f.wire.clone(), vec![current.clone()]))
                .await;
            assert!(
                f.fetch(kind, &current) == "missing",
                "replacement slot was drained by old reply"
            );
            assert!(f.context.not_banned(f.peer));
        }
    }
}

#[tokio::test]
async fn old_anchor_and_empty_hint_preserve_the_current_request() {
    for kind in KINDS {
        for empty in [false, true] {
            let mut f = Fixture::new();
            let hash = f.hash(kind);
            f.arm(kind, &hash).await;
            let other = f
                .wire
                .clone()
                .as_builder()
                .header(
                    f.wire
                        .header()
                        .into_view()
                        .as_advanced_builder()
                        .nonce(900u128)
                        .build()
                        .data(),
                )
                .build();
            let old = if empty {
                f.negative(kind, other, vec![])
            } else {
                f.positive(kind, other, false)
            };
            f.receive(old).await;
            assert!(!f.present(kind));
            f.receive(f.positive(kind, f.wire.clone(), false)).await;
            assert!(
                f.present(kind),
                "old anchor/hint retired active {kind:?} slot"
            );
            assert!(f.context.not_banned(f.peer));
        }
    }
}

#[tokio::test]
async fn duplicate_overlap_and_unsolicited_replies_preserve_request_lifecycle() {
    for kind in KINDS {
        let mut f = Fixture::new();
        let hash = f.hash(kind);
        f.arm(kind, &hash).await;
        f.receive(f.negative(kind, f.wire.clone(), vec![hash.clone(), hash.clone()]))
            .await;
        let positive = f.positive(kind, f.wire.clone(), false);
        let overlap = match positive.to_enum() {
            packed::LightClientMessageUnion::SendBlocksProof(content) => {
                let content =
                    packed::SendBlocksProofV1::from_compatible_slice(content.as_slice()).unwrap();
                packed::LightClientMessage::new_builder()
                    .set(
                        content
                            .as_builder()
                            .missing_block_hashes(vec![hash.clone()].pack())
                            .build(),
                    )
                    .build()
            }
            packed::LightClientMessageUnion::SendTransactionsProof(content) => {
                let content =
                    packed::SendTransactionsProofV1::from_compatible_slice(content.as_slice())
                        .unwrap();
                packed::LightClientMessage::new_builder()
                    .set(
                        content
                            .as_builder()
                            .missing_tx_hashes(vec![hash.clone()].pack())
                            .build(),
                    )
                    .build()
            }
            _ => unreachable!(),
        };
        f.receive(overlap).await;
        assert!(
            !f.present(kind),
            "overlap persisted a purported positive reply"
        );
        f.receive(f.positive(kind, f.wire.clone(), false)).await;
        assert!(
            f.present(kind),
            "malformed duplicates/overlap retired the active slot"
        );
        // Late copies after completion are harmless to new work and stored bytes.
        f.receive(f.positive(kind, f.wire.clone(), false)).await;
        f.receive(f.negative(kind, f.wire.clone(), vec![hash]))
            .await;
        assert!(f.present(kind));
        f.arm(kind, &packed::Byte32::new([32; 32])).await;
        assert!(f.context.not_banned(f.peer));
    }
}

#[tokio::test]
async fn matching_missing_reply_with_nonempty_proof_is_rejected_and_retried() {
    for kind in KINDS {
        let mut f = Fixture::new();
        let hash = f.hash(kind);
        f.arm(kind, &hash).await;
        let negative = f.negative(kind, f.wire.clone(), vec![hash.clone()]);
        let malformed = match negative.to_enum() {
            packed::LightClientMessageUnion::SendBlocksProof(content) => {
                let content =
                    packed::SendBlocksProofV1::from_compatible_slice(content.as_slice()).unwrap();
                packed::LightClientMessage::new_builder()
                    .set(content.as_builder().proof(f.proof.clone()).build())
                    .build()
            }
            packed::LightClientMessageUnion::SendTransactionsProof(content) => {
                let content =
                    packed::SendTransactionsProofV1::from_compatible_slice(content.as_slice())
                        .unwrap();
                packed::LightClientMessage::new_builder()
                    .set(content.as_builder().proof(f.proof.clone()).build())
                    .build()
            }
            _ => unreachable!(),
        };
        f.receive(malformed).await;
        assert!(
            f.fetch(kind, &hash) != "missing",
            "malformed reply published NotFound"
        );
        assert!(!f.present(kind));
        f.context.sent_messages().borrow_mut().clear();
        f.tick().await;
        assert!(
            !f.context.sent_messages().borrow().is_empty(),
            "malformed negative stranded retry"
        );
        f.receive(f.negative(kind, f.wire.clone(), vec![hash.clone()]))
            .await;
        assert!(f.fetch(kind, &hash) == "missing");
    }
}
