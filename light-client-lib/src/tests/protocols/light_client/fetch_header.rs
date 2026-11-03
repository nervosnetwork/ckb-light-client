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
    service::{FetchStatus, HeaderRevalidationHandle, LightClientChainService},
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
    assert!(fixture.dispatch().await.is_empty());

    let handle = fixture.service.revalidate_header(&hash).unwrap();
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Added { .. }
    ));
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Added { .. }
    ));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.last_hash(), fixture.header(20).hash());
    assert_eq!(requests[0].1.block_hashes().get(0), Some(hash.pack()));
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Fetching { .. }
    ));
    assert!(fixture.dispatch().await.is_empty());
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    for _ in 0..3 {
        let FetchStatus::Fetched { data } = handle.status().unwrap() else {
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
async fn earlier_forced_response_does_not_complete_later_handles_at_the_same_anchor() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let earlier = fixture.service.revalidate_header(&hash).unwrap();
    earlier.status().unwrap();
    let requests = fixture.dispatch().await;
    let later = fixture.service.revalidate_header(&hash).unwrap();
    later.status().unwrap();
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response.clone()).await;
    assert!(matches!(
        earlier.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(later.status().unwrap(), FetchStatus::Added { .. }));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert!(matches!(
        later.status().unwrap(),
        FetchStatus::Fetching { .. }
    ));
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        later.status().unwrap(),
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
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    handle.status().unwrap();
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response.clone()).await;
    assert!(matches!(
        handle.status().unwrap(),
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
        handle.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn old_fork_response_and_cached_header_cannot_satisfy_new_anchor_verification() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    fixture.service.fetch_header(&hash);
    let old = fixture.service.revalidate_header(&hash).unwrap();
    old.status().unwrap();
    let requests = fixture.dispatch().await;
    let old_response = fixture.response(20, &[3], &[3], &[]);

    fixture.chain.rollback_to(2, Default::default());
    fixture.chain.mine_to_with(21, |block| {
        block.as_advanced_builder().nonce(42u128).build()
    });
    assert_ne!(fixture.hash(3), hash);
    fixture.accept_tip(21);
    fixture.add_peer(2);
    let new = fixture.service.revalidate_header(&hash).unwrap();
    assert!(matches!(new.status().unwrap(), FetchStatus::Added { .. }));
    fixture.receive(requests[0].0, old_response).await;
    assert!(old.status().is_err());
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(new.status().unwrap(), FetchStatus::Added { .. }));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.last_hash(), fixture.header(21).hash());
    let missing = fixture.response(21, &[], &[], std::slice::from_ref(&hash));
    fixture.receive(requests[0].0, missing).await;
    assert_eq!(new.status().unwrap(), FetchStatus::NotFound);
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    assert_eq!(new.status().unwrap(), FetchStatus::NotFound);
    assert!(fixture.dispatch().await.is_empty());
}

// Verified extension: an unwinding caller must release the protocol thread before join/cleanup.
struct PublicationSignalOnDrop(Option<std::sync::mpsc::Sender<()>>);

impl Drop for PublicationSignalOnDrop {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_extension_publication_preserves_all_handle_states() {
    use std::{sync::mpsc, time::Duration};

    const WAIT: Duration = Duration::from_secs(30);

    // Record every outcome before asserting preservation for all operation states.
    fn observe(handle: &HeaderRevalidationHandle) -> String {
        match handle.status() {
            Ok(FetchStatus::Added { .. }) => "Added".to_owned(),
            Ok(FetchStatus::Fetching { .. }) => "Fetching".to_owned(),
            Ok(FetchStatus::Fetched { data }) => {
                format!(
                    "Fetched(number={}, hash={})",
                    u64::from(data.inner.number),
                    data.hash
                )
            }
            Ok(FetchStatus::NotFound) => "NotFound".to_owned(),
            Err(error) => format!("Error({error})"),
        }
    }

    let mut fixture = fixture();
    let completed_hash = fixture.hash(3);
    let inflight_hash = fixture.hash(4);
    let pending_hash = fixture.hash(5);
    let completed = fixture.service.revalidate_header(&completed_hash).unwrap();
    completed.status().unwrap();
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        completed.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));

    let inflight = fixture.service.revalidate_header(&inflight_hash).unwrap();
    inflight.status().unwrap();
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert!(matches!(
        inflight.status().unwrap(),
        FetchStatus::Fetching { .. }
    ));
    let pending = fixture.service.revalidate_header(&pending_hash).unwrap();
    assert!(matches!(
        pending.status().unwrap(),
        FetchStatus::Added { .. }
    ));

    fixture.chain.mine_to(21);
    let t1 = fixture.header(20).hash();
    let t2 = fixture.header(21).hash();
    assert_eq!(
        fixture.header(21).parent_hash(),
        t1,
        "must be a direct extension"
    );
    let expected_completed = format!("Fetched(number=3, hash={completed_hash})");
    let service = fixture.service.clone();
    let (published_tx, published_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let release_rx = std::sync::Mutex::new(release_rx);
    fixture
        .protocol
        .set_after_tip_publication(Arc::new(move || {
            eprintln!("Verified extension hook: storage T2 and identity published; protocol completion paused");
            published_tx
                .send(())
                .expect("Verified extension caller must be listening");
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(WAIT)
                .expect("Verified extension caller must release publication pause");
            eprintln!("Verified extension hook: caller released protocol thread");
        }));
    let (advanced_tx, advanced_rx) = mpsc::channel();
    let advanced_guard = PublicationSignalOnDrop(Some(advanced_tx));
    let caller_t2 = t2.clone();
    let caller = std::thread::spawn(move || {
        // This guard is installed before any assertion or blocking receive.
        let release_guard = PublicationSignalOnDrop(Some(release_tx));
        published_rx
            .recv_timeout(WAIT)
            .expect("verified-state path must reach publication hook");
        assert_eq!(
            service.get_tip_header().hash.pack(),
            caller_t2,
            "caller must read published T2"
        );
        let newly_created = service.revalidate_header(&pending_hash).unwrap();
        let during = [
            observe(&pending),
            observe(&inflight),
            observe(&completed),
            observe(&newly_created),
        ];
        eprintln!("Verified extension during [pending, inflight, completed, new]: {during:?}");
        drop(release_guard);
        advanced_rx
            .recv_timeout(WAIT)
            .expect("verified-state path must finish after release");
        let after = [
            observe(&pending),
            observe(&inflight),
            observe(&completed),
            observe(&newly_created),
        ];
        eprintln!("Verified extension after [pending, inflight, completed, new]: {after:?}");
        (during, after)
    });

    // Use the existing SendLastStateProof receive/verification/commit path.
    // No manual update_last_state/advance pair substitutes for that execution.
    fixture.prove_tip(21).await;
    assert_eq!(
        fixture
            .chain
            .client_storage()
            .get_tip_header()
            .calc_header_hash(),
        t2
    );
    drop(advanced_guard);
    let (during, after) = caller
        .join()
        .expect("Verified extension caller must finish");
    eprintln!("Verified extension verified T1 -> T2 extension finished and caller joined before assertions");
    let expected = [
        "Added".to_owned(),
        "Fetching".to_owned(),
        expected_completed,
        "Added".to_owned(),
    ];
    assert_eq!(
        (during, after),
        (expected.clone(), expected),
        "Verified extension verified extension must preserve operations during publication and after advancement"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn verified_tip_extensions_preserve_pending_inflight_and_completed_revalidation() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    fixture.cache(3);
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    handle.status().unwrap();
    fixture.prove_tip(21).await;
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Added { .. }
    ));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.last_hash(), fixture.header(21).hash());
    fixture.prove_tip(22).await;
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Fetching { .. }
    ));
    let newer = fixture.service.revalidate_header(&hash).unwrap();
    newer.status().unwrap();
    let response = fixture.response(21, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    fixture.prove_tip(23).await;
    for _ in 0..3 {
        let FetchStatus::Fetched { data } = handle.status().unwrap() else {
            panic!("ordinary chain advancement discarded fresh verification");
        };
        assert_eq!(data.hash, hash);
        assert_eq!(u64::from(data.inner.number), 3);
    }
    assert!(matches!(newer.status().unwrap(), FetchStatus::Added { .. }));
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.last_hash(), fixture.header(23).hash());
    let response = fixture.response(23, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    fixture.prove_tip(24).await;
    assert!(matches!(
        newer.status().unwrap(),
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
        handle.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
    assert!(fixture.dispatch().await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn verified_fork_invalidates_inflight_and_completed_revalidations() {
    let mut fixture = fixture();
    fixture.prove_tip(21).await;
    let hash = fixture.hash(3);
    let completed = fixture.service.revalidate_header(&hash).unwrap();
    completed.status().unwrap();
    let requests = fixture.dispatch().await;
    let response = fixture.response(21, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response.clone()).await;
    assert!(matches!(
        completed.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
    let inflight = fixture.service.revalidate_header(&hash).unwrap();
    inflight.status().unwrap();
    let requests = fixture.dispatch().await;
    fixture.chain.rollback_to(20, Default::default());
    fixture.chain.mine_to_with(22, |block| {
        block.as_advanced_builder().nonce(42u128).build()
    });
    fixture.prove_tip(22).await;
    for handle in [&completed, &inflight] {
        assert!(handle.status().is_err());
    }
    let newer = fixture.service.revalidate_header(&hash).unwrap();
    newer.status().unwrap();
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(newer.status().unwrap(), FetchStatus::Added { .. }));
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
        newer.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
    assert!(completed.status().is_err());
    assert!(fixture.dispatch().await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn untracked_tip_changes_before_dispatch_and_after_completion_require_new_handles() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    handle.status().unwrap();
    fixture.chain.mine_to(21);
    fixture.accept_tip(21);
    assert!(handle.status().is_err());
    assert!(fixture.dispatch().await.is_empty());
    fixture.add_peer(2);
    let fresh = fixture.service.revalidate_header(&hash).unwrap();
    fresh.status().unwrap();
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    let response = fixture.response(21, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        fresh.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
    fixture.chain.mine_to(22);
    fixture.accept_tip(22);
    assert!(fresh.status().is_err());
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_forced_result_is_terminal_and_preserves_ordinary_retry_behavior() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    handle.status().unwrap();
    fixture.service.fetch_header(&hash);
    let requests = fixture.dispatch().await;
    let missing = fixture.response(20, &[], &[], std::slice::from_ref(&hash));
    fixture.receive(requests[0].0, missing).await;
    assert_eq!(handle.status().unwrap(), FetchStatus::NotFound);
    assert_eq!(fixture.service.fetch_header(&hash), FetchStatus::NotFound);
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Added { .. }
    ));
    assert_eq!(handle.status().unwrap(), FetchStatus::NotFound);
    let retry = fixture.service.revalidate_header(&hash).unwrap();
    retry.status().unwrap();
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        retry.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
    assert_eq!(handle.status().unwrap(), FetchStatus::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn timeout_retries_on_another_peer_and_ignores_the_old_attempt() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    handle.status().unwrap();
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
        handle.status().unwrap(),
        FetchStatus::Added { .. }
    ));
    fixture.add_peer(2);
    let retried = fixture.dispatch().await;
    assert_eq!(retried.len(), 1);
    assert_ne!(requests[0].0, retried[0].0);
    fixture.receive(requests[0].0, response.clone()).await;
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Fetching { .. }
    ));
    fixture.receive(retried[0].0, response).await;
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn disconnect_retries_both_forced_and_ordinary_fetches() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    handle.status().unwrap();
    fixture.service.fetch_header(&hash);
    let requests = fixture.dispatch().await;
    fixture
        .protocol
        .disconnected(fixture.network.context(), requests[0].0)
        .await;
    assert!(matches!(
        handle.status().unwrap(),
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
        handle.status().unwrap(),
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
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    handle.status().unwrap();
    let requests = fixture.dispatch().await;
    let response = fixture.response(20, &[3], &[4], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(fixture
        .network
        .banned_since(requests[0].0, StatusCode::InvalidProof));
    assert!(matches!(
        handle.status().unwrap(),
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
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    handle.status().unwrap();
    let requests = fixture.dispatch().await;
    fixture.service.fetch_header(&hash);
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response.clone()).await;
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        fixture.peers.get_header_fetch_info(&hash.pack()),
        Some((_, 0, false))
    ));
    // The forced result is cached and visible to ordinary callers, but does not
    // clear ordinary work which was absent from its dispatch-time membership.
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Fetched { .. }
    ));
    let ordinary = fixture.dispatch().await;
    assert_eq!(ordinary.len(), 1);
    fixture.receive(ordinary[0].0, response).await;
    assert!(fixture.peers.get_header_fetch_info(&hash.pack()).is_none());
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_handle_releases_pending_tracking() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    drop(handle);
    assert!(fixture.dispatch().await.is_empty());
    assert!(fixture.peers.fetching_headers().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn pending_forced_fetches_share_one_batch_and_keep_results_separate() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let missing_hash = fixture.hash(4);
    let first = fixture.service.revalidate_header(&hash).unwrap();
    first.status().unwrap();
    let second = fixture.service.revalidate_header(&hash).unwrap();
    second.status().unwrap();
    let missing = fixture.service.revalidate_header(&missing_hash).unwrap();
    missing.status().unwrap();
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.block_hashes().len(), 2);
    let response = fixture.response(20, &[3], &[3], &[missing_hash.clone()]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        first.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
    assert!(matches!(
        second.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
    assert_eq!(missing.status().unwrap(), FetchStatus::NotFound);
    assert!(fixture.dispatch().await.is_empty());
    assert!(fixture.peers.fetching_headers().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_forced_response_does_not_discard_a_later_ordinary_fetch() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let old = fixture.service.revalidate_header(&hash).unwrap();
    old.status().unwrap();
    let requests = fixture.dispatch().await;
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.chain.mine_to(21);
    fixture.accept_tip(21);
    fixture.service.fetch_header(&hash);
    fixture.receive(requests[0].0, response).await;
    assert!(old.status().is_err());
    assert!(fixture.service.get_header(&hash).is_none());
    assert!(matches!(
        fixture.service.fetch_header(&hash),
        FetchStatus::Added { .. }
    ));
    fixture.add_peer(2);
    let fresh = fixture.service.revalidate_header(&hash).unwrap();
    fresh.status().unwrap();
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    let response = fixture.response(21, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        fresh.status().unwrap(),
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
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    handle.status().unwrap();
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
        handle.status().unwrap(),
        FetchStatus::Fetching { .. }
    ));
    assert!(fixture.peers.get_header_fetch_info(&hash.pack()).is_none());
    assert!(fixture.dispatch().await.is_empty());
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(peer, response).await;
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_inflight_handles_releases_tracking_without_discarding_ordinary_work() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let abandoned = fixture.service.revalidate_header(&hash).unwrap();
    abandoned.status().unwrap();
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

    let abandoned = fixture.service.revalidate_header(&hash).unwrap();
    abandoned.status().unwrap();
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

#[tokio::test(flavor = "multi_thread")]
async fn handle_creation_queues_its_bound_hash_without_a_status_call() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    let requests = fixture.dispatch().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].1.block_hashes().get(0), Some(hash.pack()));
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Fetching { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn handle_lifetime_follows_service_clones_not_unrelated_peers_owners() {
    let fixture = fixture();
    let hash = fixture.hash(3);
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    let clone = fixture.service.clone();
    drop(fixture.service);
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Added { .. }
    ));
    drop(clone);
    // The protocol and fixture still retain Peers, but not this service context.
    assert!(!fixture.peers.fetching_headers().is_empty());
    let error = handle.status().unwrap_err().to_string();
    assert!(error.contains("client is no longer available"), "{error}");
}

#[tokio::test(flavor = "multi_thread")]
async fn completed_handle_errors_after_its_originating_service_is_destroyed() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    let handle = fixture.service.revalidate_header(&hash).unwrap();
    let requests = fixture.dispatch().await;
    let response = fixture.response(20, &[3], &[3], &[]);
    fixture.receive(requests[0].0, response).await;
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Fetched { .. }
    ));
    drop(fixture.service);
    assert!(handle.status().is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn handles_from_distinct_clients_never_poll_another_clients_request() {
    let mut first = fixture();
    let mut second = fixture();
    let first_hash = first.hash(3);
    let second_hash = second.hash(4);
    let first_handle = first.service.revalidate_header(&first_hash).unwrap();
    let second_handle = second.service.revalidate_header(&second_hash).unwrap();
    let requests = first.dispatch().await;
    assert_eq!(requests[0].1.block_hashes().get(0), Some(first_hash.pack()));
    let requests = second.dispatch().await;
    assert_eq!(
        requests[0].1.block_hashes().get(0),
        Some(second_hash.pack())
    );
    drop(first);
    assert!(first_handle.status().is_err());
    assert!(matches!(
        second_handle.status().unwrap(),
        FetchStatus::Fetching { .. }
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn handle_creation_rejects_genesis_without_queueing_work() {
    let mut fixture = fixture();
    let hash = fixture.hash(3);
    fixture.accept_tip(0);
    assert!(fixture.service.revalidate_header(&hash).is_err());
    assert!(fixture.peers.fetching_headers().is_empty());
}
