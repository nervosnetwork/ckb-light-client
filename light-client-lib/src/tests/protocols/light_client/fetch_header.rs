use std::sync::{Arc, RwLock};

use ckb_network::{bytes::Bytes, CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_systemtime::{faketime, unix_time_as_millis};
use ckb_types::{core::HeaderView, packed, prelude::*, utilities::CBMT, H256, U256};

use crate::{
    protocols::{
        light_client::constant::{FETCH_HEADER_TX_TOKEN, REFRESH_PEERS_TOKEN},
        LastState, LightClientProtocol, Peers, PendingTxs, ProveRequest, StatusCode,
        MESSAGE_TIMEOUT,
    },
    service::{FetchHeaderOptions, FetchStatus, LightClientChainService},
    storage::{HeaderWithExtension, LightClientStorage, StorageWithChainData},
    tests::{
        prelude::*,
        utils::{MockChain, MockNetworkContext},
    },
};

struct Fixture<Chain> {
    chain: Chain,
    peers: Arc<Peers>,
    protocol: LightClientProtocol,
    service: LightClientChainService,
    network: MockNetworkContext,
}

fn fixture() -> Fixture<impl RunningChainExt> {
    let chain = MockChain::new_with_dummy_pow("fetch-header").start();
    chain.mine_to(20);
    let peers = chain.create_peers();
    let service = LightClientChainService::new(
        StorageWithChainData::new(
            chain.client_storage().clone(),
            Arc::clone(&peers),
            Arc::new(RwLock::new(PendingTxs::default())),
        ),
        Arc::new(chain.consensus().clone()),
    );
    let protocol = chain.create_light_client_protocol(Arc::clone(&peers));
    let mut fixture = Fixture {
        chain,
        peers,
        protocol,
        service,
        network: MockNetworkContext::new(SupportProtocols::LightClient),
    };
    fixture.accept_tip(20);
    fixture.add_peer(1);
    fixture
}

impl<Chain: RunningChainExt> Fixture<Chain> {
    fn header(&self, number: u64) -> HeaderView {
        self.chain
            .shared()
            .snapshot()
            .get_header_by_number(number)
            .unwrap()
    }

    fn hash(&self, number: u64) -> H256 {
        self.header(number).hash().unpack()
    }

    fn accept_tip(&mut self, number: u64) {
        self.chain.client_storage().update_last_state(
            &U256::from(number),
            &self.header(number).data(),
            &[],
        );
    }

    fn add_peer(&self, index: usize) {
        let index = PeerIndex::new(index);
        let number: u64 = self
            .chain
            .client_storage()
            .get_tip_header()
            .raw()
            .number()
            .unpack();
        self.peers.add_peer(index);
        self.peers
            .mock_prove_state(
                index,
                self.chain
                    .shared()
                    .snapshot()
                    .get_verifiable_header_by_number(number)
                    .unwrap()
                    .into(),
            )
            .unwrap();
    }

    async fn prove_tip(&mut self, number: u64) {
        self.chain.mine_to(number);
        let peer = PeerIndex::new(1);
        let snapshot = self.chain.shared().snapshot();
        let last_header = snapshot.get_verifiable_header_by_number(number).unwrap();
        let last_state = LastState::new(last_header.clone().into());
        let content = self
            .protocol
            .build_prove_request_content(
                &self.protocol.get_peer_state(&peer).unwrap(),
                last_state.as_ref(),
            )
            .await
            .unwrap();
        let start: u64 = content.start_number().unpack();
        self.peers
            .update_last_state(peer, last_state.clone())
            .unwrap();
        self.peers
            .update_prove_request(peer, ProveRequest::new(last_state, content))
            .unwrap();
        let numbers: Vec<_> = (start..number).collect();
        let response = packed::SendLastStateProof::new_builder()
            .last_header(last_header)
            .proof(self.chain.build_proof_by_numbers(number, &numbers))
            .headers(
                numbers
                    .iter()
                    .map(|number| snapshot.get_verifiable_header_by_number(*number).unwrap())
                    .collect::<Vec<_>>()
                    .pack(),
            )
            .build();
        self.receive(
            peer,
            packed::LightClientMessage::new_builder()
                .set(response)
                .build()
                .as_bytes(),
        )
        .await;
        assert!(self.network.not_banned(peer));
        assert_eq!(
            self.chain
                .client_storage()
                .get_tip_header()
                .calc_header_hash(),
            self.header(number).hash()
        );
    }

    fn cache(&self, number: u64) {
        self.chain
            .client_storage()
            .add_fetched_header(&HeaderWithExtension {
                header: self.header(number).data(),
                extension: self
                    .chain
                    .shared()
                    .snapshot()
                    .get_block_by_number(number)
                    .unwrap()
                    .extension(),
            });
    }

    fn poll(
        &self,
        hash: &H256,
        options: &mut FetchHeaderOptions,
    ) -> FetchStatus<ckb_jsonrpc_types::HeaderView> {
        self.service
            .fetch_header_with_options(hash, options)
            .unwrap()
    }

    async fn dispatch(&mut self) -> Vec<(PeerIndex, packed::GetBlocksProof)> {
        self.protocol
            .notify(self.network.context(), FETCH_HEADER_TX_TOKEN)
            .await;
        self.network
            .sent_messages()
            .borrow_mut()
            .drain(..)
            .map(|(_, peer, message)| {
                let message = packed::LightClientMessageReader::new_unchecked(&message);
                match message.to_enum() {
                    packed::LightClientMessageUnionReader::GetBlocksProof(request) => {
                        (peer, request.to_entity())
                    }
                    _ => panic!("unexpected scheduled message"),
                }
            })
            .collect()
    }

    fn response(
        &self,
        anchor: u64,
        numbers: &[u64],
        proof_numbers: &[u64],
        missing: &[H256],
    ) -> Bytes {
        let snapshot = self.chain.shared().snapshot();
        let blocks: Vec<_> = numbers
            .iter()
            .map(|number| snapshot.get_block_by_number(*number).unwrap())
            .collect();
        let content = packed::SendBlocksProofV1::new_builder()
            .last_header(snapshot.get_verifiable_header_by_number(anchor).unwrap())
            .proof(self.chain.build_proof_by_numbers(anchor, proof_numbers))
            .headers(
                blocks
                    .iter()
                    .map(|block| block.header().data())
                    .collect::<Vec<_>>()
                    .pack(),
            )
            .missing_block_hashes(
                missing
                    .iter()
                    .map(Pack::pack)
                    .collect::<Vec<packed::Byte32>>()
                    .pack(),
            )
            .blocks_uncles_hash(
                blocks
                    .iter()
                    .map(|block| block.calc_uncles_hash())
                    .collect::<Vec<_>>()
                    .pack(),
            )
            .blocks_extension(
                packed::BytesOptVec::new_builder()
                    .set(
                        blocks
                            .iter()
                            .map(|block| {
                                packed::BytesOpt::new_builder()
                                    .set(block.extension())
                                    .build()
                            })
                            .collect(),
                    )
                    .build(),
            )
            .build();
        packed::LightClientMessage::new_builder()
            .set(content)
            .build()
            .as_bytes()
    }

    async fn receive(&mut self, peer: PeerIndex, response: Bytes) {
        self.protocol
            .received(self.network.context(), peer, response)
            .await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cached_force_requires_fresh_proof_and_repeated_polling_retains_the_header() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    fixture.cache(3);
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        fixture.poll(&hash, &mut FetchHeaderOptions::new(false)),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        fixture.poll(&hash, &mut FetchHeaderOptions::default()),
        FetchStatus::Fetched { .. }
    ));
    assert!(fixture.dispatch().await.is_empty());

    let mut options = FetchHeaderOptions::new(true);
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Added { .. }
    ));
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Added { .. }
    ));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.last_hash(), fixture.header(20).hash());
    assert_eq!(requests[0].1.block_hashes().get(0), Some(hash.pack()));
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Fetching { .. }
    ));
    assert!(fixture.dispatch().await.is_empty());
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    for _ in 0..3 {
        let FetchStatus::Fetched { data } = fixture.poll(&hash, &mut options) else {
            panic!("fresh verification did not finish");
        };
        assert_eq!(data.hash, hash);
        assert_eq!(u64::from(data.inner.number), 3);
        assert_ne!(u64::from(data.inner.number), 4);
        assert!(fixture.dispatch().await.is_empty());
    }
    assert_eq!(fixture.service.get_header(&hash).unwrap().hash, hash);
    assert_eq!(
        fixture.chain.client_storage().get_block_hash(3),
        Some(hash.pack())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn earlier_forced_response_does_not_complete_later_options_at_the_same_anchor() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let mut earlier = FetchHeaderOptions::new(true);
    let mut later = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut earlier);
    let requests = fixture.dispatch().await;
    fixture.poll(&hash, &mut later);
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response.clone()).await;
    assert!(matches!(
        fixture.poll(&hash, &mut earlier),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        fixture.poll(&hash, &mut later),
        FetchStatus::Added { .. }
    ));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert!(matches!(
        fixture.poll(&hash, &mut later),
        FetchStatus::Fetching { .. }
    ));
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        fixture.poll(&hash, &mut later),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn older_ordinary_response_cannot_complete_a_forced_fetch() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Added { .. }
    ));
    let requests = fixture.dispatch().await;
    let mut options = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut options);
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response.clone()).await;
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Added { .. }
    ));
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn old_fork_response_and_cached_header_cannot_satisfy_new_anchor_verification() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    fixture.service.fetch_header(&hash);
    let mut old = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut old);
    let requests = fixture.dispatch().await;
    let old_response = fixture.response(20, &[3], &[3], &[]);

    fixture.chain.rollback_to(2, Default::default());
    fixture.chain.mine_to_with(21, |block| {
        block.as_advanced_builder().nonce(42u128).build()
    });
    assert_ne!(fixture.hash(3), hash);
    fixture.accept_tip(21);
    fixture.add_peer(2);
    let mut new = FetchHeaderOptions::new(true);
    assert!(matches!(
        fixture.poll(&hash, &mut new),
        FetchStatus::Added { .. }
    ));
    fixture.receive(requests[0].0, old_response).await;
    assert!(fixture
        .service
        .fetch_header_with_options(&hash, &mut old)
        .is_err());
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        fixture.poll(&hash, &mut new),
        FetchStatus::Added { .. }
    ));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.last_hash(), fixture.header(21).hash());
    let missing = fixture.response(21, &[], &[], std::slice::from_ref(&hash));
    fixture.receive(requests[0].0, missing).await;
    assert_eq!(fixture.poll(&hash, &mut new), FetchStatus::NotFound);
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    assert_eq!(fixture.poll(&hash, &mut new), FetchStatus::NotFound);
    assert!(fixture.dispatch().await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn verified_tip_extensions_preserve_pending_inflight_and_completed_revalidation() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    fixture.cache(3);
    let mut options = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut options);
    fixture.prove_tip(21).await;
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Added { .. }
    ));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.last_hash(), fixture.header(21).hash());
    fixture.prove_tip(22).await;
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Fetching { .. }
    ));
    let mut newer = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut newer);
    let response = fixture.response(21, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    fixture.prove_tip(23).await;
    for _ in 0..3 {
        let FetchStatus::Fetched { data } = fixture.poll(&hash, &mut options) else {
            panic!("ordinary chain advancement discarded fresh verification");
        };
        assert_eq!(data.hash, hash);
        assert_eq!(u64::from(data.inner.number), 3);
    }
    assert!(matches!(
        fixture.poll(&hash, &mut newer),
        FetchStatus::Added { .. }
    ));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.last_hash(), fixture.header(23).hash());
    let response = fixture.response(23, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    fixture.prove_tip(24).await;
    assert!(matches!(
        fixture.poll(&hash, &mut newer),
        FetchStatus::Fetched { .. }
    ));
    fixture.prove_tip(123).await;
    assert!(!fixture
        .chain
        .client_storage()
        .get_last_n_headers()
        .iter()
        .any(|(_, hash)| *hash == fixture.header(21).hash()));
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Fetched { .. }
    ));
    assert!(fixture.dispatch().await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn verified_fork_invalidates_inflight_and_completed_revalidations() {
    let mut fixture = fixture();
    fixture.prove_tip(21).await;
    let hash = fixture.hash(3);
    let mut completed = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut completed);
    let requests = fixture.dispatch().await;
    let response = fixture.response(21, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response.clone()).await;
    assert!(matches!(
        fixture.poll(&hash, &mut completed),
        FetchStatus::Fetched { .. }
    ));
    let mut inflight = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut inflight);
    let requests = fixture.dispatch().await;
    fixture.chain.rollback_to(20, Default::default());
    fixture.chain.mine_to_with(22, |block| {
        block.as_advanced_builder().nonce(42u128).build()
    });
    fixture.prove_tip(22).await;
    for options in [&mut completed, &mut inflight] {
        assert!(fixture
            .service
            .fetch_header_with_options(&hash, options)
            .is_err());
    }
    let mut newer = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut newer);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        fixture.poll(&hash, &mut newer),
        FetchStatus::Added { .. }
    ));
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.last_hash(), fixture.header(22).hash());
    let response = fixture.response(22, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        fixture.poll(&hash, &mut newer),
        FetchStatus::Fetched { .. }
    ));
    assert!(fixture
        .service
        .fetch_header_with_options(&hash, &mut completed)
        .is_err());
    assert!(fixture.dispatch().await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn untracked_tip_changes_before_dispatch_and_after_completion_require_new_options() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let mut options = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut options);
    fixture.chain.mine_to(21);
    fixture.accept_tip(21);
    assert!(fixture
        .service
        .fetch_header_with_options(&hash, &mut options)
        .is_err());
    assert!(fixture.dispatch().await.is_empty());
    fixture.add_peer(2);
    let mut fresh = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut fresh);
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    let response = fixture.response(21, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        fixture.poll(&hash, &mut fresh),
        FetchStatus::Fetched { .. }
    ));
    fixture.chain.mine_to(22);
    fixture.accept_tip(22);
    assert!(fixture
        .service
        .fetch_header_with_options(&hash, &mut fresh)
        .is_err());
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_forced_result_is_terminal_and_preserves_ordinary_retry_behavior() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let mut options = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut options);
    fixture.service.fetch_header(&hash);
    let requests = fixture.dispatch().await;
    let missing = fixture.response(20, &[], &[], std::slice::from_ref(&hash));
    fixture.receive(requests[0].0, missing).await;
    assert_eq!(fixture.poll(&hash, &mut options), FetchStatus::NotFound);
    assert_eq!(fixture.service.fetch_header(&hash), FetchStatus::NotFound);
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Added { .. }
    ));
    assert_eq!(fixture.poll(&hash, &mut options), FetchStatus::NotFound);
    let mut retry = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut retry);
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        fixture.poll(&hash, &mut retry),
        FetchStatus::Fetched { .. }
    ));
    assert_eq!(fixture.poll(&hash, &mut options), FetchStatus::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn timeout_retries_on_another_peer_and_ignores_the_old_attempt() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let mut options = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut options);
    let requests = fixture.dispatch().await;
    let response = fixture.response(20, &[3], &[3], &[]);
    let time = faketime();
    time.set_faketime(unix_time_as_millis() + MESSAGE_TIMEOUT + 1);
    fixture
        .protocol
        .notify(fixture.network.context(), REFRESH_PEERS_TOKEN)
        .await;
    fixture.network.sent_messages().borrow_mut().clear();
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Added { .. }
    ));
    fixture.add_peer(2);
    let retried = fixture.dispatch().await;
    assert_eq!(retried.len(), 1);
    assert_ne!(requests[0].0, retried[0].0);
    fixture.receive(requests[0].0, response.clone()).await;
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Fetching { .. }
    ));
    fixture.receive(retried[0].0, response).await;
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_retries_both_forced_and_ordinary_fetches() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let mut options = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut options);
    fixture.service.fetch_header(&hash);
    let requests = fixture.dispatch().await;
    fixture
        .protocol
        .disconnected(fixture.network.context(), requests[0].0)
        .await;
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Added { .. }
    ));
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetching { .. }
    ));
    fixture.add_peer(2);
    let retried = fixture.dispatch().await;
    assert_eq!(retried.len(), 1);
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(retried[0].0, response).await;
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    assert!(fixture.peers.get_header_fetch_info(&hash.pack()).is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_mmr_proof_does_not_revalidate_a_cached_header() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    fixture.cache(3);
    let mut options = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut options);
    let requests = fixture.dispatch().await;
    let response = fixture.response(20, &[3], &[4], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(fixture
        .network
        .banned_since(requests[0].0, StatusCode::InvalidProof));
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Added { .. }
    ));
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn ordinary_fetch_started_after_force_dispatch_keeps_its_own_state() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let mut options = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut options);
    let requests = fixture.dispatch().await;
    fixture.service.fetch_header(&hash);
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response.clone()).await;
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        fixture.peers.get_header_fetch_info(&hash.pack()),
        Some((_, 0, false))
    ));
    let ordinary = fixture.dispatch().await;
    assert_eq!(ordinary.len(), 1);
    fixture.receive(ordinary[0].0, response).await;
    assert!(fixture.peers.get_header_fetch_info(&hash.pack()).is_none());
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_options_release_pending_tracking_and_options_are_bound_to_one_hash() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let mut options = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut options);
    assert!(fixture
        .service
        .fetch_header_with_options(&fixture.hash(4), &mut options)
        .is_err());
    drop(options);
    assert!(fixture.dispatch().await.is_empty());
    assert!(fixture.peers.fetching_headers().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_forced_fetches_share_one_batch_and_keep_results_separate() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let missing_hash = fixture.hash(4);
    let mut first = FetchHeaderOptions::new(true);
    let mut second = FetchHeaderOptions::new(true);
    let mut missing = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut first);
    fixture.poll(&hash, &mut second);
    fixture.poll(&missing_hash, &mut missing);
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.block_hashes().len(), 2);
    let response = fixture.response(20, &[3], &[3], &[missing_hash.clone()]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        fixture.poll(&hash, &mut first),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        fixture.poll(&hash, &mut second),
        FetchStatus::Fetched { .. }
    ));
    assert_eq!(
        fixture.poll(&missing_hash, &mut missing),
        FetchStatus::NotFound
    );
    assert!(fixture.dispatch().await.is_empty());
    assert!(fixture.peers.fetching_headers().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_forced_response_does_not_discard_a_later_ordinary_fetch() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let mut old = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut old);
    let requests = fixture.dispatch().await;
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.chain.mine_to(21);
    fixture.accept_tip(21);
    fixture.service.fetch_header(&hash);
    fixture.receive(requests[0].0, response).await;
    assert!(fixture
        .service
        .fetch_header_with_options(&hash, &mut old)
        .is_err());
    assert!(fixture.service.get_header(&hash).is_none());
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Added { .. }
    ));
    fixture.add_peer(2);
    let mut fresh = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut fresh);
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    let response = fixture.response(21, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        fixture.poll(&hash, &mut fresh),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn transaction_proof_cache_writes_and_cleanup_do_not_complete_header_revalidation() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let snapshot = fixture.chain.shared().snapshot();
    let block = snapshot.get_block_by_number(3).unwrap();
    let transaction = block.transactions()[0].clone();
    let mut options = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut options);
    fixture.service.fetch_header(&hash);
    fixture
        .service
        .fetch_transaction(&transaction.hash().unpack());
    fixture
        .protocol
        .notify(fixture.network.context(), FETCH_HEADER_TX_TOKEN)
        .await;
    let messages = fixture
        .network
        .sent_messages()
        .borrow_mut()
        .drain(..)
        .collect::<Vec<_>>();
    assert_eq!(messages.len(), 2);
    let peer = messages[0].1;
    let merkle = CBMT::build_merkle_proof(
        &block
            .transactions()
            .iter()
            .map(|transaction| transaction.hash())
            .collect::<Vec<_>>(),
        &[0],
    )
    .unwrap();
    let filtered = packed::FilteredBlock::new_builder()
        .header(block.header().data())
        .witnesses_root(block.calc_witnesses_root())
        .transactions(vec![transaction.data()].pack())
        .proof(
            packed::MerkleProof::new_builder()
                .indices(merkle.indices().to_vec().pack())
                .lemmas(merkle.lemmas().to_vec().pack())
                .build(),
        )
        .build();
    let content = packed::SendTransactionsProofV1::new_builder()
        .last_header(snapshot.get_verifiable_header_by_number(20).unwrap())
        .proof(fixture.chain.build_proof_by_numbers(20, &[3]))
        .filtered_blocks(
            packed::FilteredBlockVec::new_builder()
                .set(vec![filtered])
                .build(),
        )
        .blocks_uncles_hash(vec![block.calc_uncles_hash()].pack())
        .blocks_extension(
            packed::BytesOptVec::new_builder()
                .set(vec![packed::BytesOpt::new_builder()
                    .set(block.extension())
                    .build()])
                .build(),
        )
        .build();
    let response = packed::LightClientMessage::new_builder()
        .set(content)
        .build()
        .as_bytes();
    fixture.receive(peer, response).await;
    assert!(fixture.network.not_banned(peer));
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Fetching { .. }
    ));
    assert!(fixture.peers.get_header_fetch_info(&hash.pack()).is_none());
    assert!(fixture.dispatch().await.is_empty());
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(peer, response).await;
    assert!(matches!(
        fixture.poll(&hash, &mut options),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_inflight_options_releases_tracking_without_discarding_ordinary_work() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let mut abandoned = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut abandoned);
    fixture.service.fetch_header(&hash);
    let requests = fixture.dispatch().await;
    drop(abandoned);
    assert!(fixture.dispatch().await.is_empty());
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    assert!(fixture.peers.fetching_headers().is_empty());

    let mut abandoned = FetchHeaderOptions::new(true);
    fixture.poll(&hash, &mut abandoned);
    let requests = fixture.dispatch().await;
    drop(abandoned);
    let time = faketime();
    time.set_faketime(unix_time_as_millis() + MESSAGE_TIMEOUT + 1);
    fixture
        .protocol
        .notify(fixture.network.context(), REFRESH_PEERS_TOKEN)
        .await;
    fixture.network.sent_messages().borrow_mut().clear();
    fixture.add_peer(2);
    assert!(fixture.dispatch().await.is_empty());
    assert!(fixture.peers.fetching_headers().is_empty());
    assert!(fixture
        .peers
        .get_peer(&requests[0].0)
        .unwrap()
        .get_blocks_proof_request()
        .is_some());
}
