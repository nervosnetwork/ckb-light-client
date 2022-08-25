use ckb_network::PeerIndex;
use ckb_types::{
    core::HeaderView, packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader, U256,
};
use dashmap::DashMap;
use faketime::unix_time_as_millis;
use std::sync::{Arc, RwLock};

use crate::protocols::MESSAGE_TIMEOUT;

#[derive(Default, Clone)]
pub struct Peers {
    inner: DashMap<PeerIndex, Peer>,
    // verified last N block headers
    last_headers: Arc<RwLock<Vec<HeaderView>>>,
}

#[derive(Default, Clone)]
pub struct Peer {
    // The peer is just discovered when it's `None`.
    state: PeerState,
    update_timestamp: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct LastState {
    pub(crate) tip_header: VerifiableHeader,
    pub(crate) total_difficulty: U256,
}

#[derive(Clone, Default)]
pub(crate) struct PeerState {
    // Save the header instead of the request message
    last_state: Option<LastState>,
    prove_request: Option<ProveRequest>,
    prove_state: Option<ProveState>,
    block_proof_request: Option<BlockProofRequest>,
}

#[derive(Clone)]
pub(crate) struct ProveRequest {
    last_state: LastState,
    content: packed::GetBlockSamples,
    skip_check_tau: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ProveState {
    last_state: LastState,
    reorg_last_headers: Vec<HeaderView>,
    last_headers: Vec<HeaderView>,
}

#[derive(Clone)]
pub(crate) struct BlockProofRequest {
    content: packed::GetBlockProof,
    // A flag indicates that corresponding tip block should be fetched or not.
    fetch_tip: bool,
    when_sent: u64,
}

impl LastState {
    pub(crate) fn new(tip_header: VerifiableHeader, total_difficulty: U256) -> LastState {
        LastState {
            tip_header,
            total_difficulty,
        }
    }
}

impl ProveRequest {
    pub(crate) fn new(last_state: LastState, content: packed::GetBlockSamples) -> Self {
        Self {
            last_state,
            content,
            skip_check_tau: false,
        }
    }

    pub(crate) fn get_last_header(&self) -> &VerifiableHeader {
        &self.last_state.tip_header
    }

    pub(crate) fn get_total_difficulty(&self) -> &U256 {
        &self.last_state.total_difficulty
    }

    pub(crate) fn is_same_as(
        &self,
        last_header: &VerifiableHeader,
        total_difficulty: &U256,
    ) -> bool {
        self.get_last_header() == last_header && self.get_total_difficulty() == total_difficulty
    }

    pub(crate) fn get_content(&self) -> &packed::GetBlockSamples {
        &self.content
    }

    pub(crate) fn if_skip_check_tau(&self) -> bool {
        self.skip_check_tau
    }

    pub(crate) fn skip_check_tau(&mut self) {
        self.skip_check_tau = true;
    }
}

impl ProveState {
    pub(crate) fn new_from_request(
        request: ProveRequest,
        reorg_last_headers: Vec<HeaderView>,
        last_headers: Vec<HeaderView>,
    ) -> Self {
        let ProveRequest { last_state, .. } = request;
        Self {
            last_state,
            reorg_last_headers,
            last_headers,
        }
    }

    pub(crate) fn new_child(&self, child_last_state: LastState) -> Self {
        let parent_header = self.get_last_header().header();
        let mut last_headers = self.last_headers.clone();
        let reorg_last_headers = self.reorg_last_headers.clone();
        last_headers.remove(0);
        last_headers.push(parent_header.clone());
        Self {
            last_state: child_last_state,
            reorg_last_headers,
            last_headers,
        }
    }

    pub(crate) fn get_last_header(&self) -> &VerifiableHeader {
        &self.last_state.tip_header
    }

    pub(crate) fn get_total_difficulty(&self) -> &U256 {
        &self.last_state.total_difficulty
    }

    pub(crate) fn is_same_as(
        &self,
        last_header: &VerifiableHeader,
        total_difficulty: &U256,
    ) -> bool {
        self.get_last_header() == last_header && self.get_total_difficulty() == total_difficulty
    }

    pub(crate) fn get_reorg_last_headers(&self) -> &[HeaderView] {
        &self.reorg_last_headers[..]
    }

    pub(crate) fn get_last_headers(&self) -> &[HeaderView] {
        &self.last_headers[..]
    }
}

impl BlockProofRequest {
    fn new(content: packed::GetBlockProof, fetch_tip: bool, when_sent: u64) -> Self {
        Self {
            content,
            fetch_tip,
            when_sent,
        }
    }

    pub(crate) fn is_same_as(
        &self,
        last_hash: &packed::Byte32,
        block_hashes: &[packed::Byte32],
    ) -> bool {
        let content = packed::GetBlockProof::new_builder()
            .block_hashes(block_hashes.to_vec().pack())
            .tip_hash(last_hash.to_owned())
            .build();
        self.content.as_slice() == content.as_slice()
    }

    pub(crate) fn if_fetch_tip(&self) -> bool {
        self.fetch_tip
    }
}

impl PeerState {
    pub(crate) fn get_last_state(&self) -> Option<&LastState> {
        self.last_state.as_ref()
    }

    pub(crate) fn get_prove_request(&self) -> Option<&ProveRequest> {
        self.prove_request.as_ref()
    }

    pub(crate) fn get_prove_state(&self) -> Option<&ProveState> {
        self.prove_state.as_ref()
    }

    pub(crate) fn get_block_proof_request(&self) -> Option<&BlockProofRequest> {
        self.block_proof_request.as_ref()
    }

    fn update_last_state(&mut self, last_state: LastState) {
        self.last_state = Some(last_state);
    }

    fn update_prove_request(&mut self, request: Option<ProveRequest>) {
        self.prove_request = request;
    }

    fn update_prove_state(&mut self, state: ProveState) {
        self.prove_state = Some(state);
    }

    fn update_block_proof_request(&mut self, request: Option<BlockProofRequest>) {
        self.block_proof_request = request;
    }
}

impl Peer {
    fn new(update_timestamp: u64) -> Self {
        Self {
            state: Default::default(),
            update_timestamp,
        }
    }
}

impl Peers {
    pub fn new(last_headers: Arc<RwLock<Vec<HeaderView>>>) -> Self {
        Self {
            inner: Default::default(),
            last_headers,
        }
    }

    pub(crate) fn add_peer(&self, index: PeerIndex) {
        let now = unix_time_as_millis();
        let peer = Peer::new(now);
        self.inner.insert(index, peer);
    }

    pub(crate) fn remove_peer(&self, index: PeerIndex) {
        self.inner.remove(&index);
    }

    pub(crate) fn get_peers_index(&self) -> Vec<PeerIndex> {
        self.inner.iter().map(|kv| *kv.key()).collect()
    }

    // Peers is a DashMap, return an owned PeerState to avoid the dead lock when
    // also need to update Peers later.
    pub(crate) fn get_state(&self, index: &PeerIndex) -> Option<PeerState> {
        self.inner.get(index).map(|peer| peer.state.clone())
    }

    pub(crate) fn update_last_state(&self, index: PeerIndex, last_state: LastState) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state.update_last_state(last_state);
        }
    }

    pub(crate) fn update_timestamp(&self, index: PeerIndex, timestamp: u64) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.update_timestamp = timestamp;
        }
    }

    pub(crate) fn update_prove_request(&self, index: PeerIndex, request: Option<ProveRequest>) {
        let now = unix_time_as_millis();
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state.update_prove_request(request);
            peer.update_timestamp = now;
        }
    }

    /// Update the prove state without any requests.
    pub(crate) fn update_prove_state(&self, index: PeerIndex, state: ProveState) {
        let now = unix_time_as_millis();
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state.update_prove_state(state);
            peer.update_timestamp = now;
        }
    }

    /// Commit the prove state from the previous request.
    pub(crate) fn commit_prove_state(&self, index: PeerIndex, state: ProveState) {
        *self.last_headers.write().expect("poisoned") = state.get_last_headers().to_vec();

        let now = unix_time_as_millis();
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state.update_prove_state(state);
            peer.state.update_prove_request(None);
            peer.update_timestamp = now;
        }
    }

    pub(crate) fn update_block_proof_request(
        &self,
        index: PeerIndex,
        request: Option<(packed::GetBlockProof, bool)>,
    ) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state
                .update_block_proof_request(request.map(|(content, fetch_tip)| {
                    BlockProofRequest::new(content, fetch_tip, unix_time_as_millis())
                }));
        }
    }

    pub(crate) fn get_peers_which_require_updating(&self, before_timestamp: u64) -> Vec<PeerIndex> {
        self.inner
            .iter()
            .filter_map(|item| {
                if item.value().update_timestamp < before_timestamp {
                    Some(*item.key())
                } else {
                    None
                }
            })
            .collect()
    }

    pub(crate) fn get_peers_which_have_timeout(&self, now: u64) -> Vec<PeerIndex> {
        self.inner
            .iter()
            .filter_map(|item| {
                item.value()
                    .state
                    .get_block_proof_request()
                    .and_then(|req| {
                        if now > req.when_sent + MESSAGE_TIMEOUT {
                            Some(*item.key())
                        } else {
                            None
                        }
                    })
            })
            .collect()
    }

    pub(crate) fn get_peers_which_are_proved(&self) -> Vec<(PeerIndex, ProveState)> {
        self.inner
            .iter()
            .filter_map(|item| {
                item.value()
                    .state
                    .get_prove_state()
                    .map(|state| (*item.key(), state.to_owned()))
            })
            .collect()
    }
}
