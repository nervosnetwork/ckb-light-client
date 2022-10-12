use ckb_network::PeerIndex;
use ckb_types::{
    core::HeaderView, packed, packed::Byte32, prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader, H256,
};
use dashmap::DashMap;
use faketime::unix_time_as_millis;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::protocols::MESSAGE_TIMEOUT;

#[derive(Default)]
pub struct Peers {
    inner: DashMap<PeerIndex, Peer>,
    // verified last N block headers
    last_headers: RwLock<Vec<HeaderView>>,
    // The headers are fetching, the value is:
    fetching_headers: DashMap<Byte32, FetchInfo>,
    // The transactions are fetching, the value is:
    fetching_txs: DashMap<Byte32, FetchInfo>,

    // The matched block filters to download, the key is the block hash, the value is:
    //   * if the block is proved
    //   * the downloaded block
    matched_blocks: RwLock<HashMap<H256, (bool, Option<packed::Block>)>>,
}

#[derive(Default, Clone)]
pub struct Peer {
    // The peer is just discovered when it's `None`.
    state: PeerState,
    update_timestamp: u64,
}

pub struct FetchInfo {
    // the added timestamp
    added_ts: u64,
    // the first fetch timestamp
    first_sent: u64,
    // whether the request is timeout
    timeout: bool,
    // whether the data to fetch is not on chain
    missing: bool,
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
    blocks_request: Option<BlocksRequest>,
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
    when_sent: u64,
}

#[derive(Clone)]
pub(crate) struct BlocksRequest {
    // the value indicate if the block is received
    hashes: HashMap<H256, bool>,
    when_sent: u64,
}

#[derive(Clone)]
pub(crate) struct TransactionsProofRequest {
    content: packed::GetTransactionsProof,
    when_sent: u64,
}

impl FetchInfo {
    #[cfg(test)]
    pub fn new(added_ts: u64, first_sent: u64, timeout: bool, missing: bool) -> FetchInfo {
        FetchInfo {
            added_ts,
            first_sent,
            timeout,
            missing,
        }
    }
    #[cfg(test)]
    pub fn first_sent(&self) -> u64 {
        self.first_sent
    }
    #[cfg(test)]
    pub fn missing(&self) -> bool {
        self.missing
    }
    fn new_add(added_ts: u64) -> FetchInfo {
        FetchInfo {
            added_ts,
            first_sent: 0,
            timeout: false,
            missing: false,
        }
    }
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
    pub(crate) fn new(content: packed::GetBlocksProof, when_sent: u64) -> Self {
        Self { content, when_sent }
    }

    pub(crate) fn last_hash(&self) -> Byte32 {
        self.content.last_hash()
    }

    pub(crate) fn block_hashes(&self) -> Vec<H256> {
        self.content
            .block_hashes()
            .into_iter()
            .map(|v| v.unpack())
            .collect()
    }

    pub(crate) fn check_block_hashes(
        &self,
        received_block_hashes: &[Byte32],
        missing_block_hashes: &[Byte32],
    ) -> bool {
        if self.content.block_hashes().len()
            == received_block_hashes.len() + missing_block_hashes.len()
        {
            let block_hashes = received_block_hashes
                .iter()
                .chain(missing_block_hashes)
                .collect::<HashSet<_>>();
            self.content
                .block_hashes()
                .into_iter()
                .all(|hash| block_hashes.contains(&hash))
        } else {
            false
        }
    }
}

impl BlocksRequest {
    fn new(hashes: Vec<Byte32>, when_sent: u64) -> Self {
        let hashes = hashes
            .into_iter()
            .map(|hash| (hash.unpack(), false))
            .collect::<HashMap<H256, _>>();
        Self { hashes, when_sent }
    }

    pub(crate) fn finished(&self) -> bool {
        self.hashes.values().all(|received| *received)
    }
}

impl TransactionsProofRequest {
    fn new(content: packed::GetTransactionsProof, when_sent: u64) -> Self {
        Self { content, when_sent }
    }

    pub(crate) fn last_hash(&self) -> Byte32 {
        self.content.last_hash()
    }

    pub(crate) fn tx_hashes(&self) -> Vec<H256> {
        self.content
            .tx_hashes()
            .into_iter()
            .map(|v| v.unpack())
            .collect()
    }

    pub(crate) fn check_tx_hashes(
        &self,
        received_tx_hashes: &[Byte32],
        missing_tx_hashes: &[Byte32],
    ) -> bool {
        if self.content.tx_hashes().len() == received_tx_hashes.len() + missing_tx_hashes.len() {
            let tx_hashes = received_tx_hashes
                .iter()
                .chain(missing_tx_hashes)
                .collect::<HashSet<_>>();
            self.content
                .tx_hashes()
                .into_iter()
                .all(|hash| tx_hashes.contains(&hash))
        } else {
            false
        }
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
    pub(crate) fn get_blocks_request(&self) -> Option<&BlocksRequest> {
        self.blocks_request.as_ref()
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
    fn update_blocks_request(&mut self, request: Option<BlocksRequest>) {
        self.blocks_request = request;
    }
    fn update_txs_proof_request(&mut self, request: Option<TransactionsProofRequest>) {
        self.txs_proof_request = request;
    }

    fn add_block(&mut self, block_hash: &Byte32) {
        let finished = if let Some(request) = self.blocks_request.as_mut() {
            if let Some(received) = request.hashes.get_mut(&block_hash.unpack()) {
                *received = true;
            }
            request.finished()
        } else {
            false
        };
        if finished {
            self.update_blocks_request(None);
        }
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
    pub fn new(last_headers: RwLock<Vec<HeaderView>>) -> Self {
        Self {
            inner: Default::default(),
            last_headers,
            fetching_headers: DashMap::new(),
            fetching_txs: DashMap::new(),
            matched_blocks: Default::default(),
        }
    }

    pub(crate) fn last_headers(&self) -> &RwLock<Vec<HeaderView>> {
        &self.last_headers
    }

    #[cfg(test)]
    pub(crate) fn fetching_headers(&self) -> &DashMap<Byte32, FetchInfo> {
        &self.fetching_headers
    }
    #[cfg(test)]
    pub(crate) fn fetching_txs(&self) -> &DashMap<Byte32, FetchInfo> {
        &self.fetching_txs
    }
    pub(crate) fn has_fetching_info(&self) -> bool {
        !self.fetching_headers.is_empty() || !self.fetching_txs.is_empty()
    }
    pub(crate) fn add_fetch_header(&self, block_hash: Byte32, timestamp: u64) {
        self.fetching_headers
            .insert(block_hash, FetchInfo::new_add(timestamp));
    }
    pub(crate) fn add_fetch_tx(&self, tx_hash: Byte32, timestamp: u64) {
        self.fetching_txs
            .insert(tx_hash, FetchInfo::new_add(timestamp));
    }
    pub(crate) fn get_header_fetch_info(&self, block_hash: &Byte32) -> Option<(u64, u64, bool)> {
        self.fetching_headers.get(block_hash).map(|item| {
            let info = item.value();
            (info.added_ts, info.first_sent, info.missing)
        })
    }
    pub(crate) fn get_tx_fetch_info(&self, tx_hash: &Byte32) -> Option<(u64, u64, bool)> {
        self.fetching_txs.get(tx_hash).map(|item| {
            let info = item.value();
            (info.added_ts, info.first_sent, info.missing)
        })
    }
    pub(crate) fn mark_fetching_headers_missing(&self, block_hashes: &[Byte32]) {
        for block_hash in block_hashes {
            if let Some(mut value) = self.fetching_headers.get_mut(block_hash) {
                value.missing = true;
            }
        }
    }
    pub(crate) fn mark_fetching_txs_missing(&self, tx_hashes: &[Byte32]) {
        for tx_hash in tx_hashes {
            if let Some(mut value) = self.fetching_txs.get_mut(tx_hash) {
                value.missing = true;
            }
        }
    }
    // mark all fetching hashes (headers/txs) as timeout
    pub(crate) fn mark_fetching_headers_timeout(&self, peer: PeerIndex) {
        if let Some(peer_state) = self.get_state(&peer) {
            if let Some(request) = peer_state.get_blocks_proof_request() {
                for block_hash in request.block_hashes() {
                    if let Some(mut pair) = self.fetching_headers.get_mut(&block_hash.pack()) {
                        pair.value_mut().timeout = true;
                    }
                }
            }
        }
    }
    pub(crate) fn mark_fetching_txs_timeout(&self, peer: PeerIndex) {
        if let Some(peer_state) = self.get_state(&peer) {
            if let Some(request) = peer_state.get_txs_proof_request() {
                for tx_hash in request.tx_hashes() {
                    if let Some(mut pair) = self.fetching_txs.get_mut(&tx_hash.pack()) {
                        pair.value_mut().timeout = true;
                    }
                }
            }
        }
    }
    pub(crate) fn update_fetching_headers_first_sent(
        &self,
        block_hashes: &[Byte32],
        first_sent: u64,
    ) {
        for block_hash in block_hashes {
            if let Some(mut value) = self.fetching_headers.get_mut(block_hash) {
                if value.first_sent == 0 {
                    value.first_sent = first_sent;
                }
            }
        }
    }
    pub(crate) fn update_fetching_txs_first_sent(&self, tx_hashes: &[Byte32], first_sent: u64) {
        for tx_hash in tx_hashes {
            if let Some(mut value) = self.fetching_txs.get_mut(tx_hash) {
                if value.first_sent == 0 {
                    value.first_sent = first_sent;
                }
            }
        }
    }

    pub(crate) fn matched_blocks(&self) -> &RwLock<HashMap<H256, (bool, Option<packed::Block>)>> {
        &self.matched_blocks
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

    pub(crate) fn add_block(
        &self,
        matched_blocks: &mut HashMap<H256, (bool, Option<packed::Block>)>,
        block: packed::Block,
    ) -> Option<bool> {
        let block_hash = block.header().calc_header_hash();
        for mut pair in self.inner.iter_mut() {
            pair.value_mut().state.add_block(&block_hash);
        }
        matched_blocks
            .get_mut(&block_hash.unpack())
            .map(|mut value| {
                if value.0 {
                    value.1 = Some(block);
                }
                value.0
            })
    }

    pub(crate) fn add_header(&self, block_hash: &Byte32) -> bool {
        self.fetching_headers.remove(block_hash).is_some()
    }

    pub(crate) fn add_transaction(&self, tx_hash: &Byte32, block_hash: &Byte32) -> bool {
        if self.fetching_txs.remove(tx_hash).is_some() {
            self.add_header(block_hash);
            true
        } else {
            false
        }
    }

    // The headers to fetch are which the request never send or the request is timeout
    pub(crate) fn get_headers_to_fetch(&self) -> Vec<Byte32> {
        self.fetching_headers
            .iter()
            .filter(|pair| {
                let info = pair.value();
                info.first_sent == 0 || info.timeout
            })
            .map(|pair| pair.key().clone())
            .collect()
    }
    // The txs to fetch are which the request never send or the request is timeout
    pub(crate) fn get_txs_to_fetch(&self) -> Vec<Byte32> {
        self.fetching_txs
            .iter()
            .filter(|pair| {
                let info = pair.value();
                info.first_sent == 0 || info.timeout
            })
            .map(|pair| pair.key().clone())
            .collect()
    }

    pub(crate) fn add_matched_blocks(
        &self,
        matched_blocks: &mut HashMap<H256, (bool, Option<packed::Block>)>,
        block_hashes: Vec<(Byte32, bool)>,
    ) {
        for (block_hash, proved) in block_hashes {
            matched_blocks.insert(block_hash.unpack(), (proved, None));
        }
    }
    // mark block as proved to matched blocks
    pub(crate) fn mark_matched_blocks_proved(
        &self,
        matched_blocks: &mut HashMap<H256, (bool, Option<packed::Block>)>,
        block_hashes: &[Byte32],
    ) {
        for block_hash in block_hashes {
            if let Some(mut value) = matched_blocks.get_mut(&block_hash.unpack()) {
                value.0 = true;
            }
        }
    }

    // get matched blocks which not yet downloaded and not in any BlocksRequest
    pub(crate) fn get_matched_blocks_to_prove(
        &self,
        matched_blocks: &HashMap<H256, (bool, Option<packed::Block>)>,
        limit: usize,
    ) -> Vec<Byte32> {
        let mut proof_requested_hashes = HashSet::new();
        for pair in self.inner.iter() {
            let peer_state = &pair.value().state;
            if let Some(req) = peer_state.get_blocks_proof_request() {
                for hash in req.block_hashes() {
                    proof_requested_hashes.insert(hash);
                }
            }
        }
        matched_blocks
            .iter()
            .filter_map(|(key, value)| {
                if !proof_requested_hashes.contains(key) && !value.0 {
                    Some(key.pack())
                } else {
                    None
                }
            })
            .take(limit)
            .collect()
    }
    // get matched blocks which not yet downloaded and not in any BlocksRequest
    pub(crate) fn get_matched_blocks_to_download(
        &self,
        matched_blocks: &HashMap<H256, (bool, Option<packed::Block>)>,
        limit: usize,
    ) -> Vec<Byte32> {
        let mut block_requested_hashes = HashSet::new();
        for pair in self.inner.iter() {
            let peer_state = &pair.value().state;
            if let Some(req) = peer_state.get_blocks_request() {
                for hash in req.hashes.keys() {
                    block_requested_hashes.insert(hash.clone());
                }
            }
        }
        matched_blocks
            .iter()
            .filter_map(|(key, value)| {
                let (proved, block_opt) = value;
                if !block_requested_hashes.contains(key) && *proved && block_opt.is_none() {
                    Some(key.pack())
                } else {
                    None
                }
            })
            .take(limit)
            .collect()
    }

    pub(crate) fn all_matched_blocks_downloaded(
        &self,
        matched_blocks: &HashMap<H256, (bool, Option<packed::Block>)>,
    ) -> bool {
        matched_blocks
            .values()
            .all(|(_, block_opt)| block_opt.is_some())
    }

    // remove all matched blocks info and return the downloaded blocks (sorted by block number)
    pub(crate) fn clear_matched_blocks(
        &self,
        matched_blocks: &mut HashMap<H256, (bool, Option<packed::Block>)>,
    ) -> Vec<packed::Block> {
        let mut blocks = Vec::with_capacity(matched_blocks.len());
        for (_key, (_, block_opt)) in matched_blocks.iter_mut() {
            if let Some(block) = block_opt.take() {
                blocks.push(block);
            }
        }
        matched_blocks.clear();
        blocks.sort_by_key(|b| Unpack::<u64>::unpack(&b.header().raw().number()));
        blocks
    }

    pub(crate) fn update_blocks_proof_request(
        &self,
        index: PeerIndex,
        request: Option<packed::GetBlocksProof>,
    ) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state.update_blocks_proof_request(
                request.map(|content| BlocksProofRequest::new(content, unix_time_as_millis())),
            );
        }
    }
    pub(crate) fn update_blocks_request(&self, index: PeerIndex, hashes: Option<Vec<Byte32>>) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state.update_blocks_request(
                hashes.map(|hashes| BlocksRequest::new(hashes, unix_time_as_millis())),
            );
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
                        peer_state.get_blocks_request().and_then(|req| {
                            if now > req.when_sent + MESSAGE_TIMEOUT {
                                Some(*item.key())
                            } else {
                                None
                            }
                        })
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

    pub(crate) fn get_best_proved_peers(&self, best_tip: &packed::Header) -> Vec<PeerIndex> {
        self.get_peers_which_are_proved()
            .into_iter()
            .filter(|(_, prove_state)| {
                Some(prove_state.get_last_header().header())
                    .into_iter()
                    .chain(prove_state.get_last_headers().iter())
                    .chain(prove_state.get_reorg_last_headers().iter())
                    .any(|header| header.data().as_slice() == best_tip.as_slice())
            })
            .map(|(peer_index, _)| peer_index)
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
