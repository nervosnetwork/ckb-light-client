use crate::protocols::{GET_BLOCK_PROOF_TIMEOUT, MAX_BLOCK_RPOOF_REQUESTS};
use ckb_network::PeerIndex;
use ckb_types::{
    bytes::Bytes, core::HeaderView, packed, prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader, U256,
};
use dashmap::DashMap;
use faketime::unix_time_as_millis;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

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
    pub tip_header: VerifiableHeader,
    pub total_difficulty: U256,
}

#[derive(Clone, Default)]
pub(crate) struct PeerState {
    // Save the header instead of the request message
    last_state: Option<LastState>,
    prove_request: Option<ProveRequest>,
    prove_state: Option<ProveState>,
    // The key is the serialized packed::GetBlockProof message,
    // the value is the timestamp and a flag indicates that corresponding tip block should be fetched or not.
    block_proof_requests: HashMap<Bytes, (u64, bool)>,
}

#[derive(Clone)]
pub(crate) struct ProveRequest {
    last_state: LastState,
    request: packed::GetBlockSamples,
    skip_check_tau: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ProveState {
    last_state: LastState,
    reorg_last_headers: Vec<HeaderView>,
    last_headers: Vec<HeaderView>,
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
    pub(crate) fn new(last_state: LastState, request: packed::GetBlockSamples) -> Self {
        Self {
            last_state,
            request,
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

    pub(crate) fn get_request(&self) -> &packed::GetBlockSamples {
        &self.request
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
    pub(crate) fn contains_block_proof_request(&self, request: &packed::GetBlockProof) -> bool {
        self.block_proof_requests.contains_key(&request.as_bytes())
    }
    pub(crate) fn can_insert_block_proof_request(&self) -> bool {
        self.block_proof_requests.len() < MAX_BLOCK_RPOOF_REQUESTS
    }

    fn insert_block_proof_request(&mut self, request: packed::GetBlockProof, fetch_tip: bool) {
        self.block_proof_requests
            .insert(request.as_bytes(), (unix_time_as_millis(), fetch_tip));
    }
    fn remove_block_proof_request(
        &mut self,
        request: &packed::GetBlockProof,
    ) -> Option<(u64, bool)> {
        self.block_proof_requests.remove(&request.as_bytes())
    }

    fn update_last_state(&mut self, last_state: LastState) {
        self.last_state = Some(last_state);
    }

    fn submit_prove_request(&mut self, request: ProveRequest) {
        self.prove_request = Some(request);
    }

    fn commit_prove_state(&mut self, state: ProveState) {
        self.prove_state = Some(state);
        self.prove_request = None;
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

    pub(crate) fn insert_block_proof_request(
        &self,
        index: PeerIndex,
        request: packed::GetBlockProof,
        fetch_tip: bool,
    ) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state.insert_block_proof_request(request, fetch_tip);
        }
    }
    pub(crate) fn remove_block_proof_request(
        &self,
        index: PeerIndex,
        request: &packed::GetBlockProof,
    ) -> Option<(u64, bool)> {
        self.inner
            .get_mut(&index)
            .and_then(|mut peer| peer.state.remove_block_proof_request(request))
    }
    // check all inflight requests, find peer with too many requests or have timeout request
    pub(crate) fn check_block_proof_requests(&self) -> Vec<PeerIndex> {
        let now = unix_time_as_millis();
        self.inner
            .iter()
            .filter_map(|item| {
                if item.value().state.block_proof_requests.len() > MAX_BLOCK_RPOOF_REQUESTS {
                    return Some(*item.key());
                }
                for (timestamp, _) in item.value().state.block_proof_requests.values() {
                    if now - timestamp > GET_BLOCK_PROOF_TIMEOUT {
                        return Some(*item.key());
                    }
                }
                None
            })
            .collect()
    }

    pub(crate) fn submit_prove_request(&self, index: PeerIndex, request: ProveRequest) {
        let now = unix_time_as_millis();
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state.submit_prove_request(request);
            peer.update_timestamp = now;
        }
    }

    pub(crate) fn commit_prove_state(&self, index: PeerIndex, state: ProveState) {
        *self.last_headers.write().expect("poisoned") = state.get_last_headers().to_vec();

        let now = unix_time_as_millis();
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state.commit_prove_state(state);
            peer.update_timestamp = now;
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
