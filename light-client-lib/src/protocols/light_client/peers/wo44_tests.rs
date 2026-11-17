use super::*;

#[tokio::test]
async fn wo44_valid_inflight_proof_after_recheck_is_not_penalized_or_stranded() {
    use crate::storage::{canonical::coverage, Key};
    let clock = faketime();
    clock.set_faketime(START);
    let mut f = Fixture::new();
    let hash = f.block.hash();
    f.arm(Kind::Header, &hash).await;
    let revision = coverage::scripts_revision(&f.storage).unwrap();
    coverage::save_filters(&f.storage, 1, 1, vec![(1, hash.clone())], revision).unwrap();
    let request = packed::GetBlocksProof::new_builder()
        .last_hash(f.wire.header().calc_header_hash())
        .block_hashes(vec![hash].pack())
        .build();
    f.peers
        .update_blocks_proof_request(f.peer, Some(request), true);
    let old = Captured::get(&f, Kind::Header, f.peer);
    coverage::recheck(&f.storage, 1).unwrap();
    let before = f
        .storage
        .get(Key::Meta("INDEX_REVISION_V1").into_vec())
        .unwrap();
    f.receive(f.positive(Kind::Header, f.wire.clone(), false))
        .await;
    assert!(f.context.not_banned(f.peer));
    assert!(f.context.take_disconnects().is_empty());
    assert!(slot_is_empty(&f, Kind::Header, f.peer));
    assert_eligible(&f, Kind::Header, true);
    assert!(!old.finish(&f, f.peer, true));
    assert_eq!(
        f.storage
            .get(Key::Meta("INDEX_REVISION_V1").into_vec())
            .unwrap(),
        before
    );
}

async fn hint_deadline(kind: Kind) {
    let clock = faketime();
    clock.set_faketime(START);
    let mut f = Fixture::new();
    let hash = f.hash(kind);
    f.arm(kind, &hash).await;
    let owner = Captured::get(&f, kind, f.peer);
    let hint = changed_hint(&f, 441);
    f.receive(f.negative(kind, hint.clone(), vec![])).await;
    owner.assert_same(&Captured::get(&f, kind, f.peer));
    clock.set_faketime(START + MESSAGE_TIMEOUT);
    // An independently live last-state channel must not be disconnected merely
    // because an uncorrelated proof hint could not consume its request owner.
    f.peers
        .update_last_state(f.peer, LastState::new(VerifiableHeader::from(hint.clone())))
        .unwrap();
    f.protocol
        .notify(f.context.context(), REFRESH_PEERS_TOKEN)
        .await;
    assert!(f.context.take_disconnects().is_empty());
    owner.assert_same(&Captured::get(&f, kind, f.peer));
    clock.set_faketime(START + MESSAGE_TIMEOUT + 1);
    f.peers
        .update_last_state(f.peer, LastState::new(VerifiableHeader::from(hint)))
        .unwrap();
    f.protocol
        .notify(f.context.context(), REFRESH_PEERS_TOKEN)
        .await;
    assert!(
        f.context.take_disconnects().is_empty(),
        "hinted proof deadline punished a live peer"
    );
    assert!(slot_is_empty(&f, kind, f.peer));
    assert_eligible(&f, kind, true);
    assert!(!owner.finish(&f, f.peer, true));
    assert!(f.context.not_banned(f.peer));
}

#[tokio::test]
async fn wo44_block_hint_expires_without_punishing_a_live_peer() {
    hint_deadline(Kind::Header).await;
}
#[tokio::test]
async fn wo44_transaction_hint_expires_without_punishing_a_live_peer() {
    hint_deadline(Kind::Transaction).await;
}
