use ckb_network::PeerIndex;
use ckb_types::{
    core::{HeaderView, TransactionView},
    packed,
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
    H256,
};
use dashmap::DashMap;
use faketime::unix_time_as_millis;
use std::collections::HashSet;
use std::sync::RwLock;

use crate::protocols::MESSAGE_TIMEOUT;

#[derive(Default)]
pub struct Peers {
    inner: DashMap<PeerIndex, Peer>,
    // verified last N block headers
    last_headers: RwLock<Vec<HeaderView>>,
    // Fetched headers.
    //   The key is the block hash
    //   The value is fetched header
    fetched_headers: DashMap<H256, HeaderView>,
    // The headers are fetching, the value is the first fetch timestamp and
    // whether the request is timeout
    fetching_headers: DashMap<H256, Option<(u64, bool)>>,
    // Fetch transactions.
    //   The key is the transaction hash
    //   The value is the fetched transaction and corresponding header
    fetched_txs: DashMap<H256, (TransactionView, HeaderView)>,
    // The transactions are fetching, the value is the first fetch timestamp and
    // whether the request is timeout
    fetching_txs: DashMap<H256, Option<(u64, bool)>>,
}

#[derive(Default, Clone)]
pub struct Peer {
    // The peer is just discovered when it's `None`.
    state: PeerState,
    update_timestamp: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct LastState {
    header: VerifiableHeader,
}

#[derive(Clone, Default)]
pub(crate) struct PeerState {
    // Save the header instead of the request message
    last_state: Option<LastState>,
    prove_request: Option<ProveRequest>,
    prove_state: Option<ProveState>,
    blocks_proof_request: Option<BlocksProofRequest>,
    txs_proof_request: Option<TransactionsProofRequest>,
}

#[derive(Clone)]
pub(crate) struct ProveRequest {
    last_state: LastState,
    content: packed::GetLastStateProof,
    skip_check_tau: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ProveState {
    last_state: LastState,
    reorg_last_headers: Vec<HeaderView>,
    last_headers: Vec<HeaderView>,
}

#[derive(Clone)]
pub(crate) struct BlocksProofRequest {
    content: packed::GetBlocksProof,
    // A flag indicates that corresponding tip block should be fetched or not.
    fetch_tip: bool,
    when_sent: u64,
}

#[derive(Clone)]
pub(crate) struct TransactionsProofRequest {
    content: packed::GetTransactionsProof,
    when_sent: u64,
}

impl AsRef<VerifiableHeader> for LastState {
    fn as_ref(&self) -> &VerifiableHeader {
        &self.header
    }
}

impl LastState {
    pub(crate) fn new(header: VerifiableHeader) -> LastState {
        LastState { header }
    }

    pub(crate) fn verifiable_header(&self) -> &VerifiableHeader {
        self.as_ref()
    }
}

impl ProveRequest {
    pub(crate) fn new(last_state: LastState, content: packed::GetLastStateProof) -> Self {
        Self {
            last_state,
            content,
            skip_check_tau: false,
        }
    }

    pub(crate) fn get_last_header(&self) -> &VerifiableHeader {
        self.last_state.verifiable_header()
    }

    pub(crate) fn is_same_as(&self, another: &VerifiableHeader) -> bool {
        if_verifiable_headers_are_same(self.get_last_header(), another)
    }

    pub(crate) fn get_content(&self) -> &packed::GetLastStateProof {
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

    pub(crate) fn is_parent_of(&self, child_last_state: &LastState) -> bool {
        self.get_last_header().header().hash()
            == child_last_state.verifiable_header().header().parent_hash()
    }

    pub(crate) fn get_last_header(&self) -> &VerifiableHeader {
        self.last_state.verifiable_header()
    }

    pub(crate) fn is_same_as(&self, another: &VerifiableHeader) -> bool {
        if_verifiable_headers_are_same(self.get_last_header(), another)
    }

    pub(crate) fn get_reorg_last_headers(&self) -> &[HeaderView] {
        &self.reorg_last_headers[..]
    }

    pub(crate) fn get_last_headers(&self) -> &[HeaderView] {
        &self.last_headers[..]
    }
}

impl BlocksProofRequest {
    fn new(content: packed::GetBlocksProof, fetch_tip: bool, when_sent: u64) -> Self {
        Self {
            content,
            fetch_tip,
            when_sent,
        }
    }

    pub(crate) fn block_hashes(&self) -> Vec<H256> {
        self.content
            .block_hashes()
            .into_iter()
            .map(|v| v.unpack())
            .collect()
    }

    pub(crate) fn is_same_as(
        &self,
        last_hash: &packed::Byte32,
        block_hashes: &[packed::Byte32],
    ) -> bool {
        let content = packed::GetBlocksProof::new_builder()
            .block_hashes(block_hashes.to_vec().pack())
            .last_hash(last_hash.to_owned())
            .build();
        self.content.as_slice() == content.as_slice()
    }

    pub(crate) fn if_fetch_tip(&self) -> bool {
        self.fetch_tip
    }
}

impl TransactionsProofRequest {
    fn new(content: packed::GetTransactionsProof, when_sent: u64) -> Self {
        Self { content, when_sent }
    }

    pub(crate) fn tx_hashes(&self) -> Vec<H256> {
        self.content
            .tx_hashes()
            .into_iter()
            .map(|v| v.unpack())
            .collect()
    }

    pub(crate) fn is_same_as(
        &self,
        last_hash: &packed::Byte32,
        tx_hashes: &[packed::Byte32],
    ) -> bool {
        let origin_last_hash = self.content.last_hash();
        let origin_tx_hashes: HashSet<_> = self.content.tx_hashes().into_iter().collect();
        origin_last_hash.as_slice() == last_hash.as_slice()
            && origin_tx_hashes.len() == tx_hashes.len()
            && tx_hashes
                .iter()
                .all(|tx_hash| origin_tx_hashes.contains(tx_hash))
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

    pub(crate) fn get_blocks_proof_request(&self) -> Option<&BlocksProofRequest> {
        self.blocks_proof_request.as_ref()
    }
    pub(crate) fn get_txs_proof_request(&self) -> Option<&TransactionsProofRequest> {
        self.txs_proof_request.as_ref()
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

    fn update_blocks_proof_request(&mut self, request: Option<BlocksProofRequest>) {
        self.blocks_proof_request = request;
    }
    fn update_txs_proof_request(&mut self, request: Option<TransactionsProofRequest>) {
        self.txs_proof_request = request;
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
    // only used in unit tests now
    #[cfg(test)]
    pub fn new(
        last_headers: RwLock<Vec<HeaderView>>,
        fetched_headers: DashMap<H256, HeaderView>,
        fetching_headers: DashMap<H256, Option<(u64, bool)>>,
        fetched_txs: DashMap<H256, (TransactionView, HeaderView)>,
        fetching_txs: DashMap<H256, Option<(u64, bool)>>,
    ) -> Self {
        Self {
            inner: Default::default(),
            last_headers,
            fetched_headers,
            fetching_headers,
            fetched_txs,
            fetching_txs,
        }
    }

    pub(crate) fn last_headers(&self) -> &RwLock<Vec<HeaderView>> {
        &self.last_headers
    }
    pub(crate) fn fetched_headers(&self) -> &DashMap<H256, HeaderView> {
        &self.fetched_headers
    }
    pub(crate) fn fetching_headers(&self) -> &DashMap<H256, Option<(u64, bool)>> {
        &self.fetching_headers
    }
    pub(crate) fn fetched_txs(&self) -> &DashMap<H256, (TransactionView, HeaderView)> {
        &self.fetched_txs
    }
    pub(crate) fn fetching_txs(&self) -> &DashMap<H256, Option<(u64, bool)>> {
        &self.fetching_txs
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

    pub(crate) fn add_header(&self, header: HeaderView) {
        let block_hash = header.hash().unpack();
        if self.fetching_headers.remove(&block_hash).is_some() {
            self.fetched_headers.insert(block_hash, header);
        }
    }

    pub(crate) fn add_transaction(&self, tx: TransactionView, header: HeaderView) {
        let tx_hash = tx.hash().unpack();
        if self.fetching_txs.remove(&tx_hash).is_some() {
            self.add_header(header.clone());
            self.fetched_txs.insert(tx_hash, (tx, header));
        }
    }

    // The headers to fetch are which the request never send or the request is timeout
    pub(crate) fn get_headers_to_fetch(&self) -> Vec<H256> {
        self.fetching_headers
            .iter()
            .filter(|pair| pair.value().map(|(_, timeout)| timeout).unwrap_or(true))
            .map(|pair| pair.key().clone())
            .collect()
    }
    // The txs to fetch are which the request never send or the request is timeout
    pub(crate) fn get_txs_to_fetch(&self) -> Vec<H256> {
        self.fetching_txs
            .iter()
            .filter(|pair| pair.value().map(|(_, timeout)| timeout).unwrap_or(true))
            .map(|pair| pair.key().clone())
            .collect()
    }

    // mark all fetching hashes (headers/txs) as timeout
    pub(crate) fn mark_fetching_headers_timeout(&self, peer: PeerIndex) {
        if let Some(peer_state) = self.get_state(&peer) {
            if let Some(request) = peer_state.get_blocks_proof_request() {
                for block_hash in request.block_hashes() {
                    if let Some(mut pair) = self.fetching_headers.get_mut(&block_hash) {
                        if let Some((_, ref mut timeout)) = pair.value_mut() {
                            *timeout = true;
                        }
                    }
                }
            }
        }
    }
    pub(crate) fn mark_fetching_txs_timeout(&self, peer: PeerIndex) {
        if let Some(peer_state) = self.get_state(&peer) {
            if let Some(request) = peer_state.get_txs_proof_request() {
                for tx_hash in request.tx_hashes() {
                    if let Some(mut pair) = self.fetching_txs.get_mut(&tx_hash) {
                        if let Some((_, ref mut timeout)) = pair.value_mut() {
                            *timeout = true;
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn update_blocks_proof_request(
        &self,
        index: PeerIndex,
        request: Option<(packed::GetBlocksProof, bool)>,
    ) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state
                .update_blocks_proof_request(request.map(|(content, fetch_tip)| {
                    BlocksProofRequest::new(content, fetch_tip, unix_time_as_millis())
                }));
        }
    }

    pub(crate) fn update_txs_proof_request(
        &self,
        index: PeerIndex,
        request: Option<packed::GetTransactionsProof>,
    ) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state.update_txs_proof_request(
                request
                    .map(|content| TransactionsProofRequest::new(content, unix_time_as_millis())),
            );
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
                let peer_state = &item.value().state;
                peer_state
                    .get_blocks_proof_request()
                    .and_then(|req| {
                        if now > req.when_sent + MESSAGE_TIMEOUT {
                            Some(*item.key())
                        } else {
                            None
                        }
                    })
                    .or_else(|| {
                        peer_state.get_txs_proof_request().and_then(|req| {
                            if now > req.when_sent + MESSAGE_TIMEOUT {
                                Some(*item.key())
                            } else {
                                None
                            }
                        })
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

fn if_verifiable_headers_are_same(lhs: &VerifiableHeader, rhs: &VerifiableHeader) -> bool {
    lhs.header() == rhs.header()
        && lhs.uncles_hash() == rhs.uncles_hash()
        && lhs.extension().is_none() == rhs.extension().is_none()
        && (lhs.extension().is_none()
            || (lhs
                .extension()
                .as_ref()
                .expect("checked: is not none")
                .as_slice()
                == rhs
                    .extension()
                    .as_ref()
                    .expect("checked: is not none")
                    .as_slice()))
        && lhs.total_difficulty() == rhs.total_difficulty()
}
