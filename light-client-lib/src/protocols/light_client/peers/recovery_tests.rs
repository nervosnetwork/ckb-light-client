use super::{BlocksProofRequest, TransactionsProofRequest};
use crate::{
    protocols::{
        light_client::constant::REFRESH_PEERS_TOKEN, LastState, ProveRequest, ProveState,
        StatusCode, MESSAGE_TIMEOUT,
    },
    storage::LightClientStorage,
    tests::utils::MockNetworkContext,
};
use ckb_network::{CKBProtocolHandler, PeerIndex};
use ckb_systemtime::faketime;
use ckb_types::{packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader};
use std::sync::Arc;

#[path = "../../../../tests/support/request_fixture.rs"]
mod request_fixture;
use request_fixture::{Fixture, Kind, KINDS};

const START: u64 = 100_000;

enum Captured {
    Header(BlocksProofRequest),
    Transaction(TransactionsProofRequest),
}

impl Captured {
    fn get(f: &Fixture, kind: Kind, index: PeerIndex) -> Self {
        let peer = f.peers.get_peer(&index).unwrap();
        match kind {
            Kind::Header => Self::Header(peer.get_blocks_proof_request().unwrap().clone()),
            Kind::Transaction => Self::Transaction(peer.get_txs_proof_request().unwrap().clone()),
        }
    }

    fn assert_same(&self, other: &Self) {
        self.assert_wire_and_time(other);
        assert!(
            match (self, other) {
                (Self::Header(a), Self::Header(b)) => Arc::ptr_eq(&a.owner, &b.owner),
                (Self::Transaction(a), Self::Transaction(b)) => Arc::ptr_eq(&a.owner, &b.owner),
                _ => unreachable!(),
            },
            "request owner changed"
        );
    }

    fn assert_wire_and_time(&self, other: &Self) {
        match (self, other) {
            (Self::Header(a), Self::Header(b)) => {
                assert_eq!(a.content.as_slice(), b.content.as_slice());
                assert_eq!(a.when_sent, b.when_sent);
            }
            (Self::Transaction(a), Self::Transaction(b)) => {
                assert_eq!(a.content.as_slice(), b.content.as_slice());
                assert_eq!(a.when_sent, b.when_sent);
            }
            _ => unreachable!(),
        }
    }

    fn finish(&self, f: &Fixture, index: PeerIndex, retry: bool) -> bool {
        match self {
            Self::Header(request) => f.peers.finish_blocks_proof_request(index, request, retry),
            Self::Transaction(request) => f.peers.finish_txs_proof_request(index, request, retry),
        }
    }
}

fn slot_is_empty(f: &Fixture, kind: Kind, index: PeerIndex) -> bool {
    let peer = f.peers.get_peer(&index).unwrap();
    match kind {
        Kind::Header => peer.get_blocks_proof_request().is_none(),
        Kind::Transaction => peer.get_txs_proof_request().is_none(),
    }
}

// All fetch fields are compared, including the original dispatch timestamp.
fn fetch_state(f: &Fixture, kind: Kind) -> (u64, u64, bool, bool) {
    let hash = f.hash(kind);
    let info = match kind {
        Kind::Header => f.peers.fetching_headers.get(&hash).unwrap(),
        Kind::Transaction => f.peers.fetching_txs.get(&hash).unwrap(),
    };
    (info.added_ts, info.first_sent, info.timeout, info.missing)
}

fn assert_eligible(f: &Fixture, kind: Kind, expected: bool) {
    assert_eq!(fetch_state(f, kind).2, expected, "{kind:?} retry flag");
    let eligible = match kind {
        Kind::Header => f.peers.get_headers_to_fetch(),
        Kind::Transaction => f.peers.get_txs_to_fetch(),
    };
    assert_eq!(
        eligible.contains(&f.hash(kind)),
        expected,
        "{kind:?} scheduler eligibility"
    );
}

fn observed(f: &Fixture) -> Vec<u8> {
    f.peers
        .get_state(&f.peer)
        .unwrap()
        .get_last_state()
        .unwrap()
        .as_ref()
        .header()
        .data()
        .as_slice()
        .to_vec()
}

fn accepted_state(f: &Fixture) -> (ckb_types::U256, Vec<u8>) {
    let (difficulty, header) = f.storage.get_last_state();
    (difficulty, header.as_slice().to_vec())
}

fn changed_hint(f: &Fixture, nonce: u128) -> packed::VerifiableHeader {
    f.wire
        .clone()
        .as_builder()
        .header(
            f.wire
                .header()
                .into_view()
                .as_advanced_builder()
                .nonce(nonce)
                .build()
                .data(),
        )
        .build()
}

async fn connect_proved(f: &mut Fixture, index: PeerIndex) {
    // Run the actual connection callback; the shared fixture supplies the trusted
    // proof state, as in the existing tests (not a new consensus proof claim).
    f.protocol.connected(f.context.context(), index, "3").await;
    let last = LastState::new(VerifiableHeader::from(f.wire.clone()));
    let request = ProveRequest::new(last.clone(), Default::default());
    f.peers.update_last_state(index, last).unwrap();
    f.peers
        .update_prove_request(index, request.clone())
        .unwrap();
    f.peers
        .update_prove_state(index, ProveState::new_from_request(request, vec![], vec![]))
        .unwrap();
    f.context.sent_messages().borrow_mut().clear();
}

async fn deliver_disconnects(f: &mut Fixture, expected: PeerIndex) {
    // The mock transport queues disconnects. Deliver its real handler callback;
    // merely recording a ban/disconnect would leave the peer/hash list intact.
    assert_eq!(f.context.take_disconnects(), vec![expected]);
    f.protocol.disconnected(f.context.context(), expected).await;
    assert!(f.peers.get_peer(&expected).is_none());
}

async fn deliver_ban(f: &mut Fixture) {
    assert!(f.context.has_banned(f.peer).is_some());
    f.context
        .context()
        .disconnect(f.peer, "deliver recorded transport ban")
        .unwrap();
    deliver_disconnects(f, f.peer).await;
}

async fn retry_and_complete(f: &mut Fixture, kind: Kind, survivor: PeerIndex) {
    assert_eligible(f, kind, true);
    f.context.sent_messages().borrow_mut().clear();
    f.tick().await;
    let expected_hash = f.hash(kind);
    assert!(
        f.context
            .sent_messages()
            .borrow()
            .iter()
            .any(|(_, index, bytes)| {
                if *index != survivor {
                    return false;
                }
                match (
                    kind,
                    packed::LightClientMessageReader::from_compatible_slice(bytes)
                        .unwrap()
                        .to_enum(),
                ) {
                    (
                        Kind::Header,
                        packed::LightClientMessageUnionReader::GetBlocksProof(request),
                    ) => {
                        request.block_hashes().as_slice()
                            == vec![expected_hash.clone()].pack().as_slice()
                            && request.last_hash().to_entity() == f.wire.header().calc_header_hash()
                    }
                    (
                        Kind::Transaction,
                        packed::LightClientMessageUnionReader::GetTransactionsProof(request),
                    ) => {
                        request.tx_hashes().as_slice()
                            == vec![expected_hash.clone()].pack().as_slice()
                            && request.last_hash().to_entity() == f.wire.header().calc_header_hash()
                    }
                    _ => false,
                }
            }),
        "{kind:?} retry was not dispatched to the surviving proved peer"
    );
    assert_eligible(f, kind, false);
    assert!(!slot_is_empty(f, kind, survivor));
    let reply = f.positive(kind, f.wire.clone(), false);
    f.protocol
        .received(f.context.context(), survivor, reply.as_bytes())
        .await;
    assert!(
        f.present(kind),
        "{kind:?} retry did not persist the valid result"
    );
    assert!(slot_is_empty(f, kind, survivor));
    assert!(f.context.not_banned(survivor));
}

#[tokio::test]
async fn empty_hints_preserve_owner_and_deadline_then_recover_through_timeout() {
    let clock = faketime();
    for kind in KINDS {
        clock.set_faketime(START);
        let mut f = Fixture::new();
        let hash = f.hash(kind);
        f.arm(kind, &hash).await;
        let original = Captured::get(&f, kind, f.peer);
        let original_fetch = fetch_state(&f, kind);
        assert_eq!(original_fetch.1, START);
        let accepted = accepted_state(&f);
        let before = observed(&f);
        let valid = changed_hint(&f, 900);
        assert!(f
            .protocol
            .check_verifiable_header(&valid.clone().into())
            .is_ok());
        let bad_root = valid
            .clone()
            .as_builder()
            .parent_chain_root(
                valid
                    .parent_chain_root()
                    .as_builder()
                    .children_hash(packed::Byte32::new([99; 32]))
                    .build(),
            )
            .build();
        let bad_extension = valid
            .clone()
            .as_builder()
            .extension(packed::BytesOpt::default())
            .build();
        for invalid in [bad_root, bad_extension] {
            assert_eq!(
                f.protocol
                    .check_verifiable_header(&invalid.clone().into())
                    .unwrap_err()
                    .code(),
                StatusCode::InvalidChainRoot
            );
            f.receive(f.negative(kind, invalid, vec![])).await;
            assert_eq!(observed(&f), before, "invalid hint mutated observed state");
            assert_eq!(accepted_state(&f), accepted);
            original.assert_same(&Captured::get(&f, kind, f.peer));
            assert_eq!(fetch_state(&f, kind), original_fetch);
        }
        for elapsed in [1, MESSAGE_TIMEOUT / 2, MESSAGE_TIMEOUT - 1] {
            clock.set_faketime(START + elapsed);
            f.receive(f.negative(kind, valid.clone(), vec![])).await;
            assert_eq!(observed(&f), valid.header().as_slice());
            assert_eq!(accepted_state(&f), accepted);
            original.assert_same(&Captured::get(&f, kind, f.peer));
            assert_eq!(fetch_state(&f, kind), original_fetch);
            assert!(!f
                .peers
                .get_peers_which_have_timeout(START + elapsed)
                .contains(&f.peer));
        }
        // Exactly at the original deadline is still not timed out (strict >).
        clock.set_faketime(START + MESSAGE_TIMEOUT);
        f.protocol
            .notify(f.context.context(), REFRESH_PEERS_TOKEN)
            .await;
        assert!(f.context.take_disconnects().is_empty());
        original.assert_same(&Captured::get(&f, kind, f.peer));
        assert_eligible(&f, kind, false);
        // Last-state timestamp and any last-state-proof request are fresh. Only
        // the original header/transaction proof deadline can cause this timeout.
        clock.set_faketime(START + MESSAGE_TIMEOUT + 1);
        let survivor = PeerIndex::new(2);
        connect_proved(&mut f, survivor).await;
        assert_eq!(
            f.peers
                .get_state(&f.peer)
                .unwrap()
                .get_last_state()
                .unwrap()
                .update_ts(),
            START + MESSAGE_TIMEOUT - 1
        );
        assert_eq!(
            f.peers
                .get_peers_which_have_timeout(START + MESSAGE_TIMEOUT + 1),
            vec![f.peer],
            "original proof deadline was not honored"
        );
        f.protocol
            .notify(f.context.context(), REFRESH_PEERS_TOKEN)
            .await;
        assert_eligible(&f, kind, true);
        original.assert_same(&Captured::get(&f, kind, f.peer));
        let index = f.peer;
        deliver_disconnects(&mut f, index).await;
        assert_eq!(accepted_state(&f), accepted);
        retry_and_complete(&mut f, kind, survivor).await;
        println!("A {kind:?}: invalid/repeated valid hints, original deadline, refresh/disconnect, survivor completion passed");
    }
}

fn malformed_v1(f: &Fixture, kind: Kind, truncate: bool) -> packed::LightClientMessage {
    let empty = f.negative(kind, changed_hint(f, 901), vec![]);
    // A nonempty extra-field vector with zero returned blocks is a length error.
    // Truncation additionally makes that last field structurally invalid while
    // the compatible base/outer message remains parseable.
    let bytes = match empty.to_enum() {
        packed::LightClientMessageUnion::SendBlocksProof(content) => {
            packed::SendBlocksProofV1::from_compatible_slice(content.as_slice())
                .unwrap()
                .as_builder()
                .blocks_extension(vec![packed::BytesOpt::default()])
                .build()
                .as_bytes()
        }
        packed::LightClientMessageUnion::SendTransactionsProof(content) => {
            packed::SendTransactionsProofV1::from_compatible_slice(content.as_slice())
                .unwrap()
                .as_builder()
                .blocks_extension(vec![packed::BytesOpt::default()])
                .build()
                .as_bytes()
        }
        _ => unreachable!(),
    };
    let mut bytes = bytes.to_vec();
    if truncate {
        let field_len = match kind {
            Kind::Header => packed::SendBlocksProofV1Reader::new_unchecked(&bytes)
                .blocks_extension()
                .as_slice()
                .len(),
            Kind::Transaction => packed::SendTransactionsProofV1Reader::new_unchecked(&bytes)
                .blocks_extension()
                .as_slice()
                .len(),
        };
        bytes.truncate(bytes.len() - field_len + 2);
        let total = bytes.len() as u32;
        bytes[..4].copy_from_slice(&total.to_le_bytes());
    }
    let message = match kind {
        Kind::Header => packed::LightClientMessage::new_builder()
            .set(packed::SendBlocksProofV1::new_unchecked(bytes.into()))
            .build(),
        Kind::Transaction => packed::LightClientMessage::new_builder()
            .set(packed::SendTransactionsProofV1::new_unchecked(bytes.into()))
            .build(),
    };
    assert!(packed::LightClientMessageReader::from_compatible_slice(message.as_slice()).is_ok());
    message
}

#[tokio::test]
async fn malformed_and_retired_failures_recover_through_ban_disconnect() {
    let clock = faketime();
    for kind in KINDS {
        for truncate in [false, true] {
            clock.set_faketime(START);
            let mut f = Fixture::new();
            let hash = f.hash(kind);
            f.arm(kind, &hash).await;
            let original = Captured::get(&f, kind, f.peer);
            let original_fetch = fetch_state(&f, kind);
            let prior_tip = observed(&f);
            let accepted = accepted_state(&f);
            f.receive(malformed_v1(&f, kind, truncate)).await;
            assert!(f
                .context
                .banned_since(f.peer, StatusCode::MalformedProtocolMessage));
            original.assert_same(&Captured::get(&f, kind, f.peer));
            assert_eq!(fetch_state(&f, kind), original_fetch);
            assert_eq!(observed(&f), prior_tip);
            assert_eq!(accepted_state(&f), accepted);
            assert!(!f.present(kind));
            assert_eligible(&f, kind, false);
            deliver_ban(&mut f).await;
            assert_eligible(&f, kind, true);
            let survivor = PeerIndex::new(2);
            connect_proved(&mut f, survivor).await;
            retry_and_complete(&mut f, kind, survivor).await;
            println!("B {kind:?}: malformed V1 truncate={truncate}, ban/disconnect, survivor completion passed");
        }
        clock.set_faketime(START);
        let mut f = Fixture::new();
        let hash = f.hash(kind);
        f.arm(kind, &hash).await;
        // Use the actual limiter's burst allowance of ten; no mock forced ban.
        for failure in 0..=10 {
            if failure != 0 {
                f.tick().await;
            }
            assert!(!slot_is_empty(&f, kind, f.peer));
            f.receive(f.positive(kind, f.wire.clone(), true)).await;
            assert!(slot_is_empty(&f, kind, f.peer));
            assert_eligible(&f, kind, true);
            assert!(!f.present(kind));
            if failure < 10 {
                assert!(f.context.not_banned(f.peer));
            }
        }
        assert!(f.context.banned_since(f.peer, StatusCode::InvalidProof));
        let retry_before = fetch_state(&f, kind);
        deliver_ban(&mut f).await;
        assert_eq!(
            fetch_state(&f, kind),
            retry_before,
            "disconnect lost an already retired request's retry state"
        );
        let survivor = PeerIndex::new(2);
        connect_proved(&mut f, survivor).await;
        retry_and_complete(&mut f, kind, survivor).await;
        println!("B {kind:?}: eleven matching failures, rate-limit ban after retirement, survivor completion passed");
    }
}

#[tokio::test]
async fn peer_index_reuse_preserves_new_owner_and_retry_state() {
    let clock = faketime();
    for kind in KINDS {
        clock.set_faketime(START);
        let mut f = Fixture::new();
        let hash = f.hash(kind);
        f.arm(kind, &hash).await;
        let old = Captured::get(&f, kind, f.peer);
        f.context
            .context()
            .disconnect(f.peer, "old session closes")
            .unwrap();
        let index = f.peer;
        deliver_disconnects(&mut f, index).await;
        assert_eligible(&f, kind, true);
        connect_proved(&mut f, index).await;
        f.tick().await;
        let replacement = Captured::get(&f, kind, index);
        old.assert_wire_and_time(&replacement);
        assert_eligible(&f, kind, false);
        for eligible in [false, true] {
            if eligible {
                match kind {
                    Kind::Header => f.peers.mark_fetching_headers_timeout(index),
                    Kind::Transaction => f.peers.mark_fetching_txs_timeout(index),
                }
            }
            let before = fetch_state(&f, kind);
            assert_eligible(&f, kind, eligible);
            for retry in [false, true] {
                assert!(
                    !old.finish(&f, index, retry),
                    "old session completed a replacement with identical wire/time"
                );
                replacement.assert_same(&Captured::get(&f, kind, index));
                assert_eq!(fetch_state(&f, kind), before);
                assert_eligible(&f, kind, eligible);
            }
        }
        f.receive(f.positive(kind, f.wire.clone(), false)).await;
        assert!(f.present(kind));
        assert!(slot_is_empty(&f, kind, index));
        println!("C {kind:?}: same peer index/wire/timestamp, old success/failure cannot alter new ownership or either retry state; new reply completes");
    }
}
