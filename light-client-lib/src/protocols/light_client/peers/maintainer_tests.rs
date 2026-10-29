//! Review regressions run unchanged on the published production baseline first.
use super::*;
use ckb_merkle_mountain_range::{leaf_index_to_pos, util::MemMMR};
use ckb_types::{core, utilities::merkle_mountain_range::MergeHeaderDigest};

#[tokio::test]
async fn maintainer_matched_block_reorg_reaches_idle_scheduler_and_download() {
    use crate::protocols::light_client::constant::GET_IDLE_BLOCKS_TOKEN;
    let clock = faketime();
    clock.set_faketime(START);
    let mut f = Fixture::new();
    let hash = f.block.hash();
    f.peers
        .matched_blocks()
        .write()
        .await
        .insert(hash.unpack(), (false, None));
    f.protocol
        .notify(f.context.context(), GET_IDLE_BLOCKS_TOKEN)
        .await;
    assert!(!slot_is_empty(&f, Kind::Header, f.peer));
    assert!(f
        .peers
        .get_peer(&f.peer)
        .unwrap()
        .get_blocks_proof_request()
        .unwrap()
        .should_get_blocks());
    f.receive(f.negative(Kind::Header, changed_hint(&f, 907), vec![]))
        .await;
    assert!(slot_is_empty(&f, Kind::Header, f.peer));
    let matched = f.peers.matched_blocks().read().await;
    assert_eq!(
        f.peers.get_matched_blocks_to_prove(&matched, 10),
        vec![hash.clone()]
    );
    drop(matched);
    f.protocol
        .notify(f.context.context(), GET_IDLE_BLOCKS_TOKEN)
        .await;
    assert!(slot_is_empty(&f, Kind::Header, f.peer));
    let survivor = PeerIndex::new(2);
    connect_proved(&mut f, survivor).await;
    f.protocol
        .notify(f.context.context(), GET_IDLE_BLOCKS_TOKEN)
        .await;
    assert!(!slot_is_empty(&f, Kind::Header, survivor));
    let reply = f.positive(Kind::Header, f.wire.clone(), false);
    f.protocol
        .received(f.context.context(), survivor, reply.as_bytes())
        .await;
    assert!(slot_is_empty(&f, Kind::Header, survivor));
    assert!(
        f.peers
            .matched_blocks()
            .read()
            .await
            .get(&hash.unpack())
            .unwrap()
            .0
    );
    assert!(f.context.sent_messages().borrow().iter().any(|(id, _, bytes)| {
        if *id != ckb_network::SupportProtocols::Sync.protocol_id() { return false; }
        matches!(packed::SyncMessageReader::from_compatible_slice(bytes).unwrap().to_enum(),
            packed::SyncMessageUnionReader::GetBlocks(request) if request.block_hashes().get(0).unwrap().to_entity() == hash)
    }), "verified matched block never reached the download scheduler");
    assert!(f.context.not_banned(f.peer));
    assert!(f.context.not_banned(survivor));
    assert!(f.context.take_disconnects().is_empty());
}

// Replace height two, extend the replacement, authenticate the new branch using
// the real last-state-proof handler, and retry with one connected peer only.
async fn single_peer_reorg(kind: Kind) {
    let clock = faketime();
    clock.set_faketime(START);
    let mut f = Fixture::new();
    let genesis = f.storage.get_genesis_block().header().into_view();
    let mut mmr = MemMMR::<packed::HeaderDigest, MergeHeaderDigest>::default();
    mmr.push(genesis.digest()).unwrap();
    let extension_one: packed::Bytes = mmr.get_root().unwrap().calc_mmr_hash().as_slice().pack();
    f.block = f
        .block
        .as_advanced_builder()
        .extension(Some(extension_one.clone()))
        .build();
    let header_one = packed::VerifiableHeader::new_builder()
        .header(f.block.header().data())
        .extension(
            packed::BytesOpt::new_builder()
                .set(Some(extension_one))
                .build(),
        )
        .parent_chain_root(mmr.get_root().unwrap())
        .build();
    mmr.push(f.block.header().digest()).unwrap();
    let root_two = mmr.get_root().unwrap();
    let extension_two: packed::Bytes = root_two.calc_mmr_hash().as_slice().pack();
    let extra_two = core::ExtraHashView::new(
        packed::Byte32::zero(),
        Some(extension_two.calc_raw_data_hash()),
    );
    let old_header = f
        .wire
        .header()
        .into_view()
        .as_advanced_builder()
        .parent_hash(f.block.hash())
        .extra_hash(extra_two.extra_hash())
        .build();
    f.wire = f
        .wire
        .as_builder()
        .header(old_header.data())
        .extension(
            packed::BytesOpt::new_builder()
                .set(Some(extension_two))
                .build(),
        )
        .parent_chain_root(root_two)
        .build();
    f.proof = mmr
        .gen_proof(vec![leaf_index_to_pos(1)])
        .unwrap()
        .proof_items()
        .to_vec()
        .pack();
    f.storage.update_last_state(
        &ckb_types::U256::from(3u64),
        &old_header.data(),
        &[f.block.header()],
    );
    let last = LastState::new(f.wire.clone().into());
    let prove_request = ProveRequest::new(last.clone(), Default::default());
    f.peers.update_last_state(f.peer, last).unwrap();
    f.peers
        .update_prove_request(f.peer, prove_request.clone())
        .unwrap();
    f.peers
        .update_prove_state(
            f.peer,
            ProveState::new_from_request(prove_request, vec![], vec![]),
        )
        .unwrap();
    let replacement = changed_hint(&f, 904);
    mmr.push(replacement.header().into_view().digest()).unwrap();
    let root = mmr.get_root().unwrap();
    let extension: packed::Bytes = root.calc_mmr_hash().as_slice().pack();
    let extra =
        core::ExtraHashView::new(packed::Byte32::zero(), Some(extension.calc_raw_data_hash()));
    let next = replacement
        .header()
        .into_view()
        .as_advanced_builder()
        .number(3u64)
        .parent_hash(replacement.header().calc_header_hash())
        .epoch(core::EpochNumberWithFraction::new(0, 3, 100))
        .extra_hash(extra.extra_hash())
        .build();
    let new_wire = packed::VerifiableHeader::new_builder()
        .header(next.data())
        .uncles_hash(packed::Byte32::zero())
        .extension(packed::BytesOpt::new_builder().set(Some(extension)).build())
        .parent_chain_root(root)
        .build();
    // The stored accepted checkpoint includes its real recent header history.
    let (difficulty, old_tip) = f.storage.get_last_state();
    f.storage
        .update_last_state(&difficulty, &old_tip, &[f.block.header()]);
    let hash = f.hash(kind);
    f.arm(kind, &hash).await;
    f.receive(f.negative(kind, new_wire.clone(), vec![])).await;
    assert!(slot_is_empty(&f, kind, f.peer));
    assert_eligible(&f, kind, true);
    f.tick().await;
    assert!(slot_is_empty(&f, kind, f.peer));
    f.protocol
        .notify(f.context.context(), REFRESH_PEERS_TOKEN)
        .await;
    assert!(f
        .peers
        .get_state(&f.peer)
        .unwrap()
        .get_prove_request()
        .is_some());
    let state_reply = packed::LightClientMessage::new_builder()
        .set(
            packed::SendLastStateProof::new_builder()
                .last_header(new_wire.clone())
                .headers(vec![header_one, replacement].pack())
                .proof(
                    mmr.gen_proof(vec![leaf_index_to_pos(1), leaf_index_to_pos(2)])
                        .unwrap()
                        .proof_items()
                        .to_vec()
                        .pack(),
                )
                .build(),
        )
        .build();
    f.receive(state_reply).await;
    assert_eq!(
        f.storage.get_tip_header().as_slice(),
        new_wire.header().as_slice(),
        "last-state proof did not accept reorg"
    );
    f.wire = new_wire;
    f.proof = mmr
        .gen_proof(vec![leaf_index_to_pos(1)])
        .unwrap()
        .proof_items()
        .to_vec()
        .pack();
    let index = f.peer;
    retry_and_complete(&mut f, kind, index).await;
    assert!(f.context.take_disconnects().is_empty());
    assert!(f.context.not_banned(index));
}

#[tokio::test]
async fn maintainer_one_peer_block_reorg_proves_new_tip_and_completes() {
    single_peer_reorg(Kind::Header).await;
}
#[tokio::test]
async fn maintainer_one_peer_transaction_reorg_proves_new_tip_and_completes() {
    single_peer_reorg(Kind::Transaction).await;
}

#[tokio::test]
async fn maintainer_block_handler_rechecks_owner_after_lock_await() {
    let clock = faketime();
    clock.set_faketime(START);
    let mut f = Fixture::new();
    let hash = f.hash(Kind::Header);
    f.arm(Kind::Header, &hash).await;
    let peer = f.peer;
    let peers = f.peers.clone();
    let request = peers
        .get_peer(&peer)
        .unwrap()
        .get_blocks_proof_request()
        .unwrap()
        .content
        .clone();
    peers.update_blocks_proof_request(peer, Some(request.clone()), true);
    let old = Captured::get(&f, Kind::Header, peer);
    let before = fetch_state(&f, Kind::Header);
    let mut lock = peers.matched_blocks().write().await;
    lock.insert(hash.unpack(), (false, None));
    let reply = f.positive(Kind::Header, f.wire.clone(), false);
    let context = f.context.context();
    {
        let receive = f.protocol.received(context, peer, reply.as_bytes());
        tokio::pin!(receive);
        tokio::select! {
            _ = &mut receive => panic!("handler did not wait for matched-block lock"),
            _ = tokio::task::yield_now() => {}
        }
        peers.update_blocks_proof_request(peer, Some(request), true);
        drop(lock);
        receive.await;
    }
    assert!(f.storage.get_header(&hash).is_none());
    assert_eq!(
        peers
            .matched_blocks()
            .read()
            .await
            .get(&hash.unpack())
            .unwrap(),
        &(false, None)
    );
    assert_eq!(fetch_state(&f, Kind::Header), before);
    assert!(!old.finish(&f, peer, true));
    assert!(!slot_is_empty(&f, Kind::Header, peer));
}

async fn prompt_reorg(kind: Kind) {
    let clock = faketime();
    clock.set_faketime(START);
    let mut f = Fixture::new();
    let hash = f.hash(kind);
    f.arm(kind, &hash).await;
    let old = Captured::get(&f, kind, f.peer);
    let accepted = accepted_state(&f);
    let hint = changed_hint(&f, 902);
    f.receive(f.negative(kind, hint.clone(), vec![])).await;
    assert_eq!(observed(&f), hint.header().as_slice());
    assert_eq!(accepted_state(&f), accepted);
    assert!(
        slot_is_empty(&f, kind, f.peer),
        "honest reorg left request busy"
    );
    assert_eligible(&f, kind, true);
    assert!(f.context.not_banned(f.peer));
    assert!(f.context.take_disconnects().is_empty());
    // No repeated requests for an anchor the peer just reported unavailable.
    f.context.sent_messages().borrow_mut().clear();
    for _ in 0..3 {
        f.tick().await;
        assert!(slot_is_empty(&f, kind, f.peer));
        assert_eligible(&f, kind, true);
    }
    let survivor = PeerIndex::new(2);
    connect_proved(&mut f, survivor).await;
    retry_and_complete(&mut f, kind, survivor).await;
    assert!(f.context.not_banned(f.peer));
    assert!(f.context.take_disconnects().is_empty());
    // An old asynchronous completion cannot affect an identical replacement.
    assert!(!old.finish(&f, f.peer, true));
}

#[tokio::test]
async fn maintainer_block_reorg_recovers_promptly() {
    prompt_reorg(Kind::Header).await;
}
#[tokio::test]
async fn maintainer_transaction_reorg_recovers_promptly() {
    prompt_reorg(Kind::Transaction).await;
}

#[derive(Clone, Copy, Debug)]
enum Bad {
    ExtraData,
    ReplayedHint,
    InvalidHint,
    Extra,
    Subset,
    Unrelated,
    Duplicate,
    Overlap,
    Unsolicited,
    DifferentAnchor,
}

fn unwanted(f: &Fixture, kind: Kind, bad: Bad) -> packed::LightClientMessage {
    let hash = f.hash(kind);
    let extra = packed::Byte32::new([78; 32]);
    match bad {
        Bad::ExtraData => match f.positive(kind, f.wire.clone(), false).to_enum() {
            packed::LightClientMessageUnion::SendBlocksProof(m) => {
                let content =
                    packed::SendBlocksProofV1::from_compatible_slice(m.as_slice()).unwrap();
                let unrequested = f
                    .block
                    .header()
                    .as_advanced_builder()
                    .nonce(999u128)
                    .build();
                packed::LightClientMessage::new_builder()
                    .set(
                        content
                            .as_builder()
                            .headers(vec![f.block.header().data(), unrequested.data()].pack())
                            .blocks_uncles_hash(vec![f.block.calc_uncles_hash(); 2].pack())
                            .blocks_extension(vec![packed::BytesOpt::default(); 2])
                            .build(),
                    )
                    .build()
            }
            packed::LightClientMessageUnion::SendTransactionsProof(m) => {
                let content =
                    packed::SendTransactionsProofV1::from_compatible_slice(m.as_slice()).unwrap();
                let block = content.filtered_blocks().get(0).unwrap();
                let tx = f.block.transactions()[0]
                    .clone()
                    .as_advanced_builder()
                    .version(99u32)
                    .build();
                let block = block
                    .as_builder()
                    .transactions(vec![f.block.transactions()[0].data(), tx.data()].pack())
                    .build();
                packed::LightClientMessage::new_builder()
                    .set(content.as_builder().filtered_blocks(vec![block]).build())
                    .build()
            }
            _ => unreachable!(),
        },
        Bad::ReplayedHint => f.negative(kind, changed_hint(f, 905), vec![]),
        Bad::InvalidHint => f.negative(
            kind,
            changed_hint(f, 906)
                .as_builder()
                .extension(packed::BytesOpt::default())
                .build(),
            vec![],
        ),
        Bad::Extra => f.negative(kind, f.wire.clone(), vec![hash, extra]),
        Bad::Subset => f.negative(kind, f.wire.clone(), vec![]),
        Bad::Unrelated => f.negative(kind, f.wire.clone(), vec![extra]),
        Bad::Duplicate => f.negative(kind, f.wire.clone(), vec![hash.clone(), hash]),
        Bad::Unsolicited => large_positive(f, kind, f.wire.clone()),
        Bad::DifferentAnchor => large_positive(f, kind, changed_hint(f, 903)),
        Bad::Overlap => match f.positive(kind, f.wire.clone(), false).to_enum() {
            packed::LightClientMessageUnion::SendBlocksProof(m) => {
                packed::LightClientMessage::new_builder()
                    .set(
                        packed::SendBlocksProofV1::from_compatible_slice(m.as_slice())
                            .unwrap()
                            .as_builder()
                            .missing_block_hashes(vec![hash].pack())
                            .build(),
                    )
                    .build()
            }
            packed::LightClientMessageUnion::SendTransactionsProof(m) => {
                packed::LightClientMessage::new_builder()
                    .set(
                        packed::SendTransactionsProofV1::from_compatible_slice(m.as_slice())
                            .unwrap()
                            .as_builder()
                            .missing_tx_hashes(vec![hash].pack())
                            .build(),
                    )
                    .build()
            }
            _ => unreachable!(),
        },
    }
}

fn large_positive(
    f: &Fixture,
    kind: Kind,
    wire: packed::VerifiableHeader,
) -> packed::LightClientMessage {
    const COUNT: usize = 512;
    match f.positive(kind, wire, false).to_enum() {
        packed::LightClientMessageUnion::SendBlocksProof(m) => {
            let content = packed::SendBlocksProofV1::from_compatible_slice(m.as_slice()).unwrap();
            packed::LightClientMessage::new_builder()
                .set(
                    content
                        .as_builder()
                        .headers(vec![f.block.header().data(); COUNT].pack())
                        .blocks_uncles_hash(vec![f.block.calc_uncles_hash(); COUNT].pack())
                        .blocks_extension(vec![packed::BytesOpt::default(); COUNT])
                        .build(),
                )
                .build()
        }
        packed::LightClientMessageUnion::SendTransactionsProof(m) => {
            let content =
                packed::SendTransactionsProofV1::from_compatible_slice(m.as_slice()).unwrap();
            let block = content.filtered_blocks().get(0).unwrap();
            packed::LightClientMessage::new_builder()
                .set(
                    content
                        .as_builder()
                        .filtered_blocks(vec![block; COUNT])
                        .blocks_uncles_hash(vec![f.block.calc_uncles_hash(); COUNT].pack())
                        .blocks_extension(vec![packed::BytesOpt::default(); COUNT])
                        .build(),
                )
                .build()
        }
        _ => unreachable!(),
    }
}

async fn rejection(kind: Kind, cases: &[Bad]) {
    let clock = faketime();
    for &bad in cases {
        clock.set_faketime(START);
        let mut f = Fixture::new();
        let hash = f.hash(kind);
        f.arm(kind, &hash).await;
        if matches!(bad, Bad::ReplayedHint) {
            f.receive(unwanted(&f, kind, bad)).await;
            assert!(slot_is_empty(&f, kind, f.peer));
            assert_eligible(&f, kind, true);
        }
        if matches!(bad, Bad::Unsolicited) {
            f.receive(f.positive(kind, f.wire.clone(), false)).await;
            assert!(slot_is_empty(&f, kind, f.peer));
            // Put independent work on a second peer before the flood.
            let survivor = PeerIndex::new(2);
            connect_proved(&mut f, survivor).await;
        }
        let owner = (!matches!(bad, Bad::Unsolicited | Bad::ReplayedHint))
            .then(|| Captured::get(&f, kind, f.peer));
        let accepted = accepted_state(&f);
        let observed_before = observed(&f);
        let expected = match bad {
            Bad::Unsolicited | Bad::ReplayedHint => StatusCode::PeerIsNotOnProcess,
            Bad::InvalidHint => StatusCode::InvalidChainRoot,
            _ => StatusCode::UnexpectedResponse,
        };
        let message = unwanted(&f, kind, bad);
        let status = f
            .protocol
            .try_process(&f.context.context(), f.peer, message.as_reader().to_enum())
            .await;
        assert_eq!(status.code(), expected);
        for attempt in 0..=10 {
            f.receive(unwanted(&f, kind, bad)).await;
            if let Some(owner) = &owner {
                owner.assert_same(&Captured::get(&f, kind, f.peer));
                assert_eligible(&f, kind, false);
                assert!(!f.present(kind));
            } else {
                assert!(slot_is_empty(&f, kind, f.peer));
            }
            assert_eq!(accepted_state(&f), accepted);
            assert_eq!(observed(&f), observed_before);
            if attempt < 10 {
                assert!(f.context.not_banned(f.peer));
            }
        }
        assert!(
            f.context.banned_since(f.peer, expected),
            "{kind:?} {bad:?} flood escaped penalty"
        );
        deliver_ban(&mut f).await;
        let survivor = PeerIndex::new(2);
        if owner.is_some() || matches!(bad, Bad::ReplayedHint) {
            assert_eligible(&f, kind, true);
            connect_proved(&mut f, survivor).await;
            retry_and_complete(&mut f, kind, survivor).await;
        } else {
            // Completion survived the unsolicited flood; new work is schedulable.
            assert!(f.present(kind));
            let next = packed::Byte32::new([79; 32]);
            assert_eq!(f.fetch(kind, &next), "added");
            f.tick().await;
            assert!(!slot_is_empty(&f, kind, survivor));
            let reply = f.negative(kind, f.wire.clone(), vec![next.clone()]);
            f.protocol
                .received(f.context.context(), survivor, reply.as_bytes())
                .await;
            assert_eq!(f.fetch(kind, &next), "missing");
            assert!(slot_is_empty(&f, kind, survivor));
            assert!(f.context.not_banned(survivor));
        }
        println!("maintainer {kind:?} {bad:?}: limiter ban, delivered disconnect, preserved owner, survivor completion");
    }
}

#[tokio::test]
async fn maintainer_block_mismatched_sets_are_penalized() {
    rejection(
        Kind::Header,
        &[
            Bad::Extra,
            Bad::ExtraData,
            Bad::Subset,
            Bad::Unrelated,
            Bad::Duplicate,
            Bad::Overlap,
        ],
    )
    .await;
}
#[tokio::test]
async fn maintainer_transaction_mismatched_sets_are_penalized() {
    rejection(
        Kind::Transaction,
        &[
            Bad::Extra,
            Bad::ExtraData,
            Bad::Subset,
            Bad::Unrelated,
            Bad::Duplicate,
            Bad::Overlap,
        ],
    )
    .await;
}
#[tokio::test]
async fn maintainer_block_unsolicited_is_penalized() {
    rejection(Kind::Header, &[Bad::Unsolicited]).await;
}
#[tokio::test]
async fn maintainer_transaction_unsolicited_is_penalized() {
    rejection(Kind::Transaction, &[Bad::Unsolicited]).await;
}
#[tokio::test]
async fn maintainer_block_different_anchor_data_is_penalized() {
    rejection(Kind::Header, &[Bad::DifferentAnchor]).await;
}
#[tokio::test]
async fn maintainer_transaction_different_anchor_data_is_penalized() {
    rejection(Kind::Transaction, &[Bad::DifferentAnchor]).await;
}

#[tokio::test]
async fn maintainer_forged_and_replayed_hints_are_bounded() {
    for kind in KINDS {
        rejection(kind, &[Bad::InvalidHint, Bad::ReplayedHint]).await;
    }
}
