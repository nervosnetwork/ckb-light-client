use ckb_network::PeerIndex;
use ckb_systemtime::unix_time_as_millis;
use ckb_types::{
    core::{BlockNumber, HeaderView},
    packed,
    packed::Byte32,
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
    H256, U256,
};
use dashmap::DashMap;
use std::{
    collections::{HashMap, HashSet},
    fmt, mem,
    sync::RwLock,
};

use super::prelude::*;
use crate::protocols::{Status, StatusCode, MESSAGE_TIMEOUT};

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

    // Data:
    // - Cached check point index.
    // - Block filter hashes between current cached check point and next cached check point.
    //   - Exclude the cached check point.
    //   - Include at the next cached check point.
    cached_block_filter_hashes: RwLock<(u32, Vec<packed::Byte32>)>,

    #[cfg(not(test))]
    max_outbound_peers: u32,

    #[cfg(test)]
    max_outbound_peers: RwLock<u32>,

    check_point_interval: BlockNumber,
    start_check_point: (u32, packed::Byte32),
}

#[derive(Clone)]
pub struct Peer {
    // The peer is just discovered when it's `None`.
    state: PeerState,
    blocks_proof_request: Option<BlocksProofRequest>,
    blocks_request: Option<BlocksRequest>,
    txs_proof_request: Option<TransactionsProofRequest>,
    check_points: CheckPoints,
    latest_block_filter_hashes: LatestBlockFilterHashes,
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

#[derive(Clone)]
pub(crate) struct LastState {
    header: VerifiableHeader,
    update_ts: u64,
}

/*
 * ```plantuml
 * @startuml
 * state "Initialized"                as st1
 * state "RequestFirstLastState"      as st2
 * state "OnlyHasLastState"           as st3
 * state "RequestFirstLastStateProof" as st4
 * state "Ready"                      as st5
 * state "RequestNewLastState"        as st6
 * state "RequestNewLastStateProof"   as st7
 *
 * [*] ->   st1 : Connect Peer
 * st1 ->   st2 : Send    GetLastState
 * st2 -D-> st3 : Receive SendLastState
 * st3 ->   st4 : Send    GetLastStateProof
 * st4 ->   st5 : Receive SendLastStateProof
 * st5 -U-> st6 : Send    GetLastState
 * st6 ->   st5 : Receive SendLastState
 * st5 -D-> st7 : Send    GetLastStateProof
 * st7 ->   st5 : Receive SendLastStateProof
 * @endum
 * ```
 */
#[derive(Clone)]
pub(crate) enum PeerState {
    Initialized,
    RequestFirstLastState {
        when_sent: u64,
    },
    OnlyHasLastState {
        last_state: LastState,
    },
    RequestFirstLastStateProof {
        last_state: LastState,
        request: ProveRequest,
        when_sent: u64,
    },
    Ready {
        last_state: LastState,
        prove_state: ProveState,
    },
    RequestNewLastState {
        last_state: LastState,
        prove_state: ProveState,
        when_sent: u64,
    },
    RequestNewLastStateProof {
        last_state: LastState,
        prove_state: ProveState,
        request: ProveRequest,
        when_sent: u64,
    },
}

#[derive(Clone)]
pub(crate) struct ProveRequest {
    last_state: LastState,
    content: packed::GetLastStateProof,
    skip_check_tau: bool,
    long_fork_detected: bool,
}

#[derive(Clone)]
pub(crate) struct ProveState {
    last_state: LastState,
    reorg_last_headers: Vec<HeaderView>,
    last_headers: Vec<HeaderView>,
}

#[derive(Clone)]
pub(crate) struct BlocksProofRequest {
    content: packed::GetBlocksProof,
    when_sent: u64,
    should_get_blocks: bool,
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

#[derive(Clone)]
pub(crate) struct CheckPoints {
    check_point_interval: BlockNumber,
    // The index of the first check point in the memory.
    index_of_first_check_point: u32,
    // Exists at least 1 check point.
    // N.B. Do NOT leak any API that could make this vector be empty.
    inner: Vec<packed::Byte32>,
}

#[derive(Clone)]
pub(crate) struct LatestBlockFilterHashes {
    // The previous block number of the first block filter hash.
    check_point_number: BlockNumber,
    inner: Vec<packed::Byte32>,
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

impl fmt::Display for LastState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let header = self.header.header();
        if f.alternate() {
            write!(
                f,
                "LastState {{ num: {}, hash: {:#x}, ts: {} }}",
                header.number(),
                header.hash(),
                self.update_ts
            )
        } else {
            write!(f, "{}", header.number())
        }
    }
}

impl LastState {
    pub(crate) fn new(header: VerifiableHeader) -> LastState {
        LastState {
            header,
            update_ts: unix_time_as_millis(),
        }
    }

    pub(crate) fn total_difficulty(&self) -> U256 {
        self.as_ref().total_difficulty()
    }

    pub(crate) fn header(&self) -> &HeaderView {
        self.as_ref().header()
    }

    pub(crate) fn update_ts(&self) -> u64 {
        self.update_ts
    }

    pub(crate) fn is_same_as(&self, another: &Self) -> bool {
        if_verifiable_headers_are_same(&self.header, &another.header)
    }
}

impl fmt::Display for ProveRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let tau_status = if self.skip_check_tau {
            "skipped"
        } else {
            "normal"
        };
        if f.alternate() {
            write!(
                f,
                "LastState {{ last_state: {:#}, tau: {}, fork: {} }}",
                self.last_state, tau_status, self.long_fork_detected,
            )
        } else {
            write!(
                f,
                "{} (tau: {}, fork: {})",
                self.last_state, tau_status, self.long_fork_detected,
            )
        }
    }
}

impl ProveRequest {
    pub(crate) fn new(last_state: LastState, content: packed::GetLastStateProof) -> Self {
        Self {
            last_state,
            content,
            skip_check_tau: false,
            long_fork_detected: false,
        }
    }

    pub(crate) fn get_last_header(&self) -> &VerifiableHeader {
        self.last_state.as_ref()
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

    pub(crate) fn if_long_fork_detected(&self) -> bool {
        self.long_fork_detected
    }

    pub(crate) fn long_fork_detected(&mut self) {
        self.long_fork_detected = true;
    }
}

impl fmt::Display for ProveState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "ProveState {{ last_state: {:#}", self.last_state)?;
            if self.reorg_last_headers.is_empty() {
                write!(f, ", reorg: None")?;
            } else {
                let len = self.reorg_last_headers.len();
                let start = self.reorg_last_headers[0].number();
                let end = self.reorg_last_headers[len - 1].number();
                write!(f, ", reorg: [{}, {}]", start, end)?;
            }
            if self.last_headers.is_empty() {
                write!(f, ", last: None")?;
            } else {
                let len = self.last_headers.len();
                let start = self.last_headers[0].number();
                let end = self.last_headers[len - 1].number();
                write!(f, ", last: [{}, {}]", start, end)?;
            }
            write!(f, " }}")
        } else {
            write!(
                f,
                "{} (reorg: {}, last: {})",
                self.last_state,
                self.reorg_last_headers.len(),
                self.last_headers.len()
            )
        }
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

    pub(crate) fn new_child(&self, child_last_state: LastState, last_n_blocks: usize) -> Self {
        let parent_header = self.get_last_header().header();
        let mut last_headers = self.last_headers.clone();
        let reorg_last_headers = self.reorg_last_headers.clone();
        // To avoid unlimited memory growth.
        if last_headers.len() >= last_n_blocks {
            last_headers.remove(0);
        }
        last_headers.push(parent_header.clone());
        Self {
            last_state: child_last_state,
            reorg_last_headers,
            last_headers,
        }
    }

    pub(crate) fn is_parent_of(&self, child_last_state: &LastState) -> bool {
        self.get_last_header()
            .header()
            .is_parent_of(child_last_state.header())
    }

    pub(crate) fn get_last_header(&self) -> &VerifiableHeader {
        self.last_state.as_ref()
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
    pub(crate) fn new(
        content: packed::GetBlocksProof,
        when_sent: u64,
        should_get_blocks: bool,
    ) -> Self {
        Self {
            content,
            when_sent,
            should_get_blocks,
        }
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

    pub(crate) fn should_get_blocks(&self) -> bool {
        self.should_get_blocks
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

impl CheckPoints {
    fn new(
        check_point_interval: BlockNumber,
        index_of_first_check_point: u32,
        first_check_point: packed::Byte32,
    ) -> Self {
        Self {
            check_point_interval,
            index_of_first_check_point,
            inner: vec![first_check_point],
        }
    }

    fn get_start_index(&self) -> u32 {
        self.index_of_first_check_point
    }

    fn get_check_points(&self) -> Vec<packed::Byte32> {
        self.inner.clone()
    }

    fn number_of_first_check_point(&self) -> BlockNumber {
        self.check_point_interval * BlockNumber::from(self.index_of_first_check_point)
    }

    fn number_of_last_check_point(&self) -> BlockNumber {
        let first = self.number_of_first_check_point();
        let count = self.inner.len() as BlockNumber;
        first + self.check_point_interval * (count - 1)
    }

    fn number_of_next_check_point(&self) -> BlockNumber {
        self.number_of_last_check_point()
    }

    fn if_require_next_check_point(&self, last_proved_number: BlockNumber) -> bool {
        self.number_of_next_check_point() + self.check_point_interval * 2 <= last_proved_number
    }

    fn add_check_points(
        &mut self,
        last_proved_number: BlockNumber,
        start_number: BlockNumber,
        check_points: &[packed::Byte32],
    ) -> Result<Option<BlockNumber>, Status> {
        if check_points.is_empty() {
            return Err(StatusCode::CheckPointsIsEmpty.into());
        }
        if start_number % self.check_point_interval != 0 {
            let errmsg = format!(
                "check points should at `{} * N` but got {}",
                self.check_point_interval, start_number
            );
            return Err(StatusCode::CheckPointsIsUnaligned.with_context(errmsg));
        }
        let next_number = self.number_of_next_check_point();
        if start_number != next_number {
            let errmsg = format!(
                "expect starting from {} but got {}",
                next_number, start_number
            );
            return Err(StatusCode::CheckPointsIsUnexpected.with_context(errmsg));
        }
        let prev_last_check_point = &self.inner[self.inner.len() - 1];
        let curr_first_check_point = &check_points[0];
        if prev_last_check_point != curr_first_check_point {
            let errmsg = format!(
                "expect hash for number {} is {:#x} but got {:#x}",
                start_number, prev_last_check_point, curr_first_check_point
            );
            return Err(StatusCode::CheckPointsIsUnexpected.with_context(errmsg));
        }
        if check_points.len() < 2 {
            let errmsg = format!(
                "expect at least 2 check points but got only {}",
                check_points.len()
            );
            return Err(StatusCode::CheckPointsIsUnexpected.with_context(errmsg));
        }
        let check_points_len = check_points.len() as BlockNumber;
        if start_number + self.check_point_interval * check_points_len <= last_proved_number {
            self.inner.extend_from_slice(&check_points[1..]);
        } else if check_points.len() > 2 {
            let end = check_points.len() - 2;
            self.inner.extend_from_slice(&check_points[1..=end]);
        }
        if self.if_require_next_check_point(last_proved_number) {
            Ok(Some(self.number_of_next_check_point()))
        } else {
            Ok(None)
        }
    }

    fn remove_first_n_check_points(&mut self, n: usize) {
        self.index_of_first_check_point += n as u32;
        self.inner.drain(..n);
    }
}

impl LatestBlockFilterHashes {
    fn new(check_point_number: BlockNumber) -> Self {
        Self {
            check_point_number,
            inner: Vec::new(),
        }
    }

    #[cfg(test)]
    fn mock(check_point_number: BlockNumber, inner: Vec<packed::Byte32>) -> Self {
        Self {
            check_point_number,
            inner,
        }
    }

    fn get_check_point_number(&self) -> BlockNumber {
        self.check_point_number
    }

    fn get_last_number(&self) -> BlockNumber {
        self.get_check_point_number() + self.inner.len() as BlockNumber
    }

    fn get_hashes(&self) -> Vec<packed::Byte32> {
        self.inner.clone()
    }

    fn clear(&mut self) {
        self.inner.clear();
    }

    fn reset(&mut self, new_check_point_number: BlockNumber) {
        self.check_point_number = new_check_point_number;
        self.clear();
    }

    fn update_latest_block_filter_hashes(
        &mut self,
        last_proved_number: BlockNumber,
        finalized_check_point_number: BlockNumber,
        finalized_check_point: &packed::Byte32,
        start_number: BlockNumber,
        parent_block_filter_hash: &packed::Byte32,
        mut block_filter_hashes: &[packed::Byte32],
    ) -> Result<Option<BlockNumber>, Status> {
        if block_filter_hashes.is_empty() {
            return Err(StatusCode::BlockFilterHashesIsEmpty.into());
        }
        // Check block numbers.
        if finalized_check_point_number >= last_proved_number {
            let errmsg = format!(
                "finalized check point ({}) is not less than proved number ({})",
                finalized_check_point_number, last_proved_number
            );
            return Err(StatusCode::Ignore.with_context(errmsg));
        }
        let check_point_number = self.get_check_point_number();
        if finalized_check_point_number != check_point_number {
            let errmsg = format!(
                "finalized check point ({}) is not same as cached ({})",
                finalized_check_point_number, check_point_number
            );
            return Err(StatusCode::Ignore.with_context(errmsg));
        }
        let mut end_number = start_number + block_filter_hashes.len() as BlockNumber - 1;
        if finalized_check_point_number >= end_number {
            let errmsg = format!(
                "finalized check point ({}) is not less than end number ({})",
                finalized_check_point_number, end_number,
            );
            return Err(StatusCode::Ignore.with_context(errmsg));
        }
        if start_number > last_proved_number {
            let errmsg = format!(
                "start number ({}) is greater than the proved number ({})",
                start_number, last_proved_number
            );
            return Err(StatusCode::Ignore.with_context(errmsg));
        }
        let last_filter_number = self.get_last_number();
        if start_number > last_filter_number + 1 {
            let errmsg = format!(
                "start number ({}) is continuous with last filter block number ({})",
                start_number, last_filter_number
            );
            return Err(StatusCode::Ignore.with_context(errmsg));
        }
        if end_number > last_proved_number {
            let diff = end_number - last_proved_number;
            let new_length = block_filter_hashes.len() - diff as usize;
            block_filter_hashes = &block_filter_hashes[..new_length];
            end_number = last_proved_number;
        }
        // Check block filter hashes.
        let (start_index_for_old, start_index_for_new) = if start_number
            <= finalized_check_point_number
        {
            let diff = finalized_check_point_number - start_number;
            let index = diff as usize;
            let check_hash = &block_filter_hashes[index];
            if check_hash != finalized_check_point {
                let errmsg = format!(
                    "check point for block {} is {:#x} but check hash is {:#}",
                    finalized_check_point_number, finalized_check_point, check_hash
                );
                return Err(StatusCode::BlockFilterHashesIsUnexpected.with_context(errmsg));
            }
            (0, index + 1)
        } else if start_number == finalized_check_point_number + 1 {
            if parent_block_filter_hash != finalized_check_point {
                let errmsg = format!(
                    "check point for block {} is {:#x} but parent hash is {:#}",
                    finalized_check_point_number, finalized_check_point, parent_block_filter_hash
                );
                return Err(StatusCode::BlockFilterHashesIsUnexpected.with_context(errmsg));
            }
            (0, 0)
        } else {
            let diff = start_number - finalized_check_point_number;
            let index = diff as usize - 2;
            let filter_hash = &self.inner[index];
            if filter_hash != parent_block_filter_hash {
                let errmsg = format!(
                    "filter hash for block {} is {:#x} but parent hash is {:#}",
                    start_number - 1,
                    filter_hash,
                    parent_block_filter_hash
                );
                return Err(StatusCode::BlockFilterHashesIsUnexpected.with_context(errmsg));
            }
            (index + 1, 0)
        };
        for (index, (old_hash, new_hash)) in self.inner[start_index_for_old..]
            .iter()
            .zip(block_filter_hashes[start_index_for_new..].iter())
            .enumerate()
        {
            if old_hash != new_hash {
                let number = start_number + (start_index_for_old + index) as BlockNumber;
                let errmsg = format!(
                    "old filter hash for block {} is {:#x} but new is {:#}",
                    number, old_hash, new_hash
                );
                return Err(StatusCode::Ignore.with_context(errmsg));
            }
        }
        // Update block filter hashes.
        let index = start_index_for_new + self.inner[start_index_for_old..].len();
        self.inner.extend_from_slice(&block_filter_hashes[index..]);
        if end_number < last_proved_number {
            Ok(Some(end_number + 1))
        } else {
            Ok(None)
        }
    }
}

impl Default for PeerState {
    fn default() -> Self {
        Self::Initialized
    }
}

impl fmt::Display for PeerState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let fullname = format!("PeerState::{}", self.name());
        if f.alternate() {
            match self {
                Self::Initialized => {
                    write!(f, "{}", fullname)
                }
                Self::RequestFirstLastState { when_sent } => {
                    write!(f, "{} {{ when_sent: {} }}", fullname, when_sent)
                }
                Self::OnlyHasLastState { last_state } => {
                    write!(f, "{} {{ last_state: {} }}", fullname, last_state)
                }
                Self::RequestFirstLastStateProof {
                    last_state,
                    request,
                    when_sent,
                } => {
                    write!(f, "{} {{ last_state: {}", fullname, last_state)?;
                    write!(f, ", request: {}", request)?;
                    write!(f, ", when_sent: {}", when_sent)?;
                    write!(f, "}}")
                }
                Self::Ready {
                    last_state,
                    prove_state,
                } => {
                    write!(f, "{} {{ last_state: {}", fullname, last_state)?;
                    write!(f, ", prove_state: {}", prove_state)?;
                    write!(f, "}}")
                }
                Self::RequestNewLastState {
                    last_state,
                    prove_state,
                    when_sent,
                } => {
                    write!(f, "{} {{ last_state: {}", fullname, last_state)?;
                    write!(f, ", prove_state: {}", prove_state)?;
                    write!(f, ", when_sent: {}", when_sent)?;
                    write!(f, "}}")
                }
                Self::RequestNewLastStateProof {
                    last_state,
                    prove_state,
                    request,
                    when_sent,
                } => {
                    write!(f, "{} {{ last_state: {}", fullname, last_state)?;
                    write!(f, ", prove_state: {}", prove_state)?;
                    write!(f, ", request: {}", request)?;
                    write!(f, ", when_sent: {}", when_sent)?;
                    write!(f, "}}")
                }
            }
        } else {
            match self {
                Self::Initialized | Self::RequestFirstLastState { .. } => {
                    write!(f, "{}", fullname)
                }
                Self::OnlyHasLastState { last_state, .. }
                | Self::RequestFirstLastStateProof { last_state, .. }
                | Self::Ready { last_state, .. }
                | Self::RequestNewLastState { last_state, .. }
                | Self::RequestNewLastStateProof { last_state, .. } => {
                    write!(f, "{} {{ last_state: {} }}", fullname, last_state)
                }
            }
        }
    }
}

impl PeerState {
    fn name(&self) -> &'static str {
        match self {
            Self::Initialized => "Initialized",
            Self::RequestFirstLastState { .. } => "RequestFirstLastState",
            Self::OnlyHasLastState { .. } => "OnlyHasLastState",
            Self::RequestFirstLastStateProof { .. } => "RequestFirstLastStateProof",
            Self::Ready { .. } => "Ready",
            Self::RequestNewLastState { .. } => "RequestNewLastState",
            Self::RequestNewLastStateProof { .. } => "RequestNewLastStateProof",
        }
    }

    fn take(&mut self) -> Self {
        let mut ret = Self::Initialized;
        mem::swap(self, &mut ret);
        ret
    }

    pub(crate) fn get_last_state(&self) -> Option<&LastState> {
        match self {
            Self::Initialized | Self::RequestFirstLastState { .. } => None,
            Self::OnlyHasLastState { ref last_state, .. }
            | Self::RequestFirstLastStateProof { ref last_state, .. }
            | Self::Ready { ref last_state, .. }
            | Self::RequestNewLastState { ref last_state, .. }
            | Self::RequestNewLastStateProof { ref last_state, .. } => Some(last_state),
        }
    }

    pub(crate) fn get_prove_request(&self) -> Option<&ProveRequest> {
        match self {
            Self::RequestFirstLastStateProof { ref request, .. }
            | Self::RequestNewLastStateProof { ref request, .. } => Some(request),
            Self::Initialized
            | Self::OnlyHasLastState { .. }
            | Self::RequestFirstLastState { .. }
            | Self::Ready { .. }
            | Self::RequestNewLastState { .. } => None,
        }
    }

    pub(crate) fn get_prove_state(&self) -> Option<&ProveState> {
        match self {
            Self::Ready {
                ref prove_state, ..
            }
            | Self::RequestNewLastState {
                ref prove_state, ..
            }
            | Self::RequestNewLastStateProof {
                ref prove_state, ..
            } => Some(prove_state),
            Self::Initialized
            | Self::RequestFirstLastState { .. }
            | Self::OnlyHasLastState { .. }
            | Self::RequestFirstLastStateProof { .. } => None,
        }
    }

    fn request_last_state(self, when_sent: u64) -> Result<Self, Status> {
        match self {
            Self::Initialized => {
                let new_state = Self::RequestFirstLastState { when_sent };
                Ok(new_state)
            }
            Self::Ready {
                last_state,
                prove_state,
            } => {
                let new_state = Self::RequestNewLastState {
                    last_state,
                    prove_state,
                    when_sent,
                };
                Ok(new_state)
            }
            _ => {
                let errmsg = format!("{} request last state", self);
                Err(StatusCode::IncorrectLastState.with_context(errmsg))
            }
        }
    }

    fn receive_last_state(mut self, new_last_state: LastState) -> Result<Self, Status> {
        match self {
            Self::RequestFirstLastState { .. } => {
                let new_state = Self::OnlyHasLastState {
                    last_state: new_last_state,
                };
                Ok(new_state)
            }
            Self::RequestNewLastState { prove_state, .. } => {
                let new_state = Self::Ready {
                    last_state: new_last_state,
                    prove_state,
                };
                Ok(new_state)
            }
            Self::OnlyHasLastState { ref mut last_state }
            | Self::RequestFirstLastStateProof {
                ref mut last_state, ..
            }
            | Self::Ready {
                ref mut last_state, ..
            }
            | Self::RequestNewLastStateProof {
                ref mut last_state, ..
            } => {
                *last_state = new_last_state;
                Ok(self)
            }
            _ => {
                let errmsg = format!("{} receive last state", self);
                Err(StatusCode::IncorrectLastState.with_context(errmsg))
            }
        }
    }

    fn request_last_state_proof(
        mut self,
        new_request: ProveRequest,
        new_when_sent: u64,
    ) -> Result<Self, Status> {
        match self {
            Self::OnlyHasLastState { last_state, .. } => {
                let new_state = Self::RequestFirstLastStateProof {
                    last_state,
                    request: new_request,
                    when_sent: new_when_sent,
                };
                Ok(new_state)
            }
            Self::Ready {
                last_state,
                prove_state,
                ..
            } => {
                let new_state = Self::RequestNewLastStateProof {
                    last_state,
                    prove_state,
                    request: new_request,
                    when_sent: new_when_sent,
                };
                Ok(new_state)
            }
            Self::RequestFirstLastStateProof {
                ref mut request,
                ref mut when_sent,
                ..
            }
            | Self::RequestNewLastStateProof {
                ref mut request,
                ref mut when_sent,
                ..
            } => {
                *request = new_request;
                *when_sent = new_when_sent;
                Ok(self)
            }
            _ => {
                let errmsg = format!("{} request last state proof", self);
                Err(StatusCode::IncorrectLastState.with_context(errmsg))
            }
        }
    }

    fn receive_last_state_proof(self, new_prove_state: ProveState) -> Result<Self, Status> {
        match self {
            Self::OnlyHasLastState { last_state }
            | Self::RequestFirstLastStateProof { last_state, .. }
            | Self::Ready { last_state, .. }
            | Self::RequestNewLastStateProof { last_state, .. } => {
                let new_state = Self::Ready {
                    last_state,
                    prove_state: new_prove_state,
                };
                Ok(new_state)
            }
            _ => {
                let errmsg = format!("{} receive last state proof", self);
                Err(StatusCode::IncorrectLastState.with_context(errmsg))
            }
        }
    }

    fn require_new_last_state(&self, before_ts: u64) -> bool {
        match self {
            Self::Initialized => true,
            Self::OnlyHasLastState { ref last_state } | Self::Ready { ref last_state, .. } => {
                last_state.update_ts() < before_ts
            }
            Self::RequestFirstLastState { .. }
            | Self::RequestFirstLastStateProof { .. }
            | Self::RequestNewLastState { .. }
            | Self::RequestNewLastStateProof { .. } => false,
        }
    }

    fn require_new_last_state_proof(&self) -> bool {
        match self {
            Self::Ready {
                ref last_state,
                ref prove_state,
            } => !prove_state.is_same_as(last_state.as_ref()),
            Self::OnlyHasLastState { .. } => true,
            Self::Initialized
            | Self::RequestFirstLastState { .. }
            | Self::RequestFirstLastStateProof { .. }
            | Self::RequestNewLastState { .. }
            | Self::RequestNewLastStateProof { .. } => false,
        }
    }

    fn when_sent_request(&self) -> Option<u64> {
        match self {
            Self::Initialized | Self::OnlyHasLastState { .. } | Self::Ready { .. } => None,
            Self::RequestFirstLastState { when_sent }
            | Self::RequestFirstLastStateProof { when_sent, .. }
            | Self::RequestNewLastState { when_sent, .. }
            | Self::RequestNewLastStateProof { when_sent, .. } => Some(*when_sent),
        }
    }
}

impl Peer {
    fn new(check_point_interval: BlockNumber, start_check_point: (u32, packed::Byte32)) -> Self {
        let check_points = CheckPoints::new(
            check_point_interval,
            start_check_point.0,
            start_check_point.1,
        );
        let check_point_number = check_point_interval * BlockNumber::from(start_check_point.0);
        let latest_block_filter_hashes = LatestBlockFilterHashes::new(check_point_number);
        Self {
            state: Default::default(),
            blocks_proof_request: None,
            blocks_request: None,
            txs_proof_request: None,
            check_points,
            latest_block_filter_hashes,
        }
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
            self.blocks_request = None;
        }
    }
}

impl Peers {
    pub fn new(
        max_outbound_peers: u32,
        check_point_interval: BlockNumber,
        start_check_point: (u32, packed::Byte32),
    ) -> Self {
        #[cfg(test)]
        let max_outbound_peers = RwLock::new(max_outbound_peers);

        Self {
            inner: Default::default(),
            last_headers: Default::default(),
            fetching_headers: DashMap::new(),
            fetching_txs: DashMap::new(),
            matched_blocks: Default::default(),
            cached_block_filter_hashes: Default::default(),
            max_outbound_peers,
            check_point_interval,
            start_check_point,
        }
    }

    pub(crate) fn required_peers_count(&self) -> usize {
        let required_peers_count = ((self.get_max_outbound_peers() + 1) / 2) as usize;
        if required_peers_count == 0 {
            panic!("max outbound peers shouldn't be zero!");
        }
        required_peers_count
    }

    pub(crate) fn calc_check_point_number(&self, index: u32) -> BlockNumber {
        self.check_point_interval * BlockNumber::from(index)
    }

    fn calc_cached_check_point_index_when_sync_at(&self, number: BlockNumber) -> u32 {
        // Examples of `input -> output`, denote `check_point_interval` as `i`:
        // - [0] -> 0
        // - [1, i] -> 0
        // - [i+1, 2i] -> 1
        // - ... ...
        // - [ki+1, (k+1)i] -> k
        (number.saturating_sub(1) / self.check_point_interval) as u32
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
    pub(crate) fn mark_fetching_headers_timeout(&self, peer_index: PeerIndex) {
        if let Some(peer) = self.get_peer(&peer_index) {
            if let Some(request) = peer.get_blocks_proof_request() {
                for block_hash in request.block_hashes() {
                    if let Some(mut pair) = self.fetching_headers.get_mut(&block_hash.pack()) {
                        pair.value_mut().timeout = true;
                    }
                }
            }
        }
    }
    pub(crate) fn mark_fetching_txs_timeout(&self, peer_index: PeerIndex) {
        if let Some(peer) = self.get_peer(&peer_index) {
            if let Some(request) = peer.get_txs_proof_request() {
                for tx_hash in request.tx_hashes() {
                    if let Some(mut pair) = self.fetching_txs.get_mut(&tx_hash.pack()) {
                        pair.value_mut().timeout = true;
                    }
                }
            }
        }
    }
    pub(crate) fn fetching_idle_headers(&self, block_hashes: &[Byte32], now: u64) {
        for block_hash in block_hashes {
            if let Some(mut value) = self.fetching_headers.get_mut(block_hash) {
                if value.first_sent == 0 {
                    value.first_sent = now;
                }
                value.timeout = false;
            }
        }
    }
    pub(crate) fn fetching_idle_txs(&self, tx_hashes: &[Byte32], now: u64) {
        for tx_hash in tx_hashes {
            if let Some(mut value) = self.fetching_txs.get_mut(tx_hash) {
                if value.first_sent == 0 {
                    value.first_sent = now;
                }
                value.timeout = false;
            }
        }
    }

    pub(crate) fn matched_blocks(&self) -> &RwLock<HashMap<H256, (bool, Option<packed::Block>)>> {
        &self.matched_blocks
    }

    #[cfg(not(test))]
    pub(crate) fn get_max_outbound_peers(&self) -> u32 {
        self.max_outbound_peers
    }

    #[cfg(test)]
    pub(crate) fn get_max_outbound_peers(&self) -> u32 {
        *self.max_outbound_peers.read().expect("poisoned")
    }

    #[cfg(test)]
    pub(crate) fn set_max_outbound_peers(&self, max_outbound_peers: u32) {
        *self.max_outbound_peers.write().expect("poisoned") = max_outbound_peers;
    }

    pub(crate) fn add_peer(&self, index: PeerIndex) {
        let peer = Peer::new(self.check_point_interval, self.start_check_point.clone());
        self.inner.insert(index, peer);
    }

    pub(crate) fn remove_peer(&self, index: PeerIndex) {
        self.mark_fetching_headers_timeout(index);
        self.mark_fetching_txs_timeout(index);
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

    pub(crate) fn get_peer(&self, index: &PeerIndex) -> Option<Peer> {
        self.inner.get(index).map(|peer| peer.clone())
    }

    #[cfg(test)]
    pub(crate) fn mock_initialized(&self, index: PeerIndex) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            _ = peer.state.take();
        }
    }

    #[cfg(test)]
    pub(crate) fn mock_prove_request(
        &self,
        index: PeerIndex,
        request: ProveRequest,
    ) -> Result<(), Status> {
        let last_state = LastState::new(request.get_last_header().to_owned());
        self.request_last_state(index)?;
        self.update_last_state(index, last_state)?;
        self.update_prove_request(index, request)
    }

    #[cfg(test)]
    pub(crate) fn mock_prove_state(
        &self,
        index: PeerIndex,
        tip_header: VerifiableHeader,
    ) -> Result<(), Status> {
        let last_state = LastState::new(tip_header);
        let request = ProveRequest::new(last_state.clone(), Default::default());
        let prove_state =
            ProveState::new_from_request(request.clone(), Default::default(), Default::default());
        self.request_last_state(index)?;
        self.update_last_state(index, last_state)?;
        self.update_prove_request(index, request)?;
        self.update_prove_state(index, prove_state)
    }

    pub(crate) fn request_last_state(&self, index: PeerIndex) -> Result<(), Status> {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            let now = unix_time_as_millis();
            peer.state = peer.state.take().request_last_state(now)?;
        }
        Ok(())
    }

    pub(crate) fn update_last_state(
        &self,
        index: PeerIndex,
        last_state: LastState,
    ) -> Result<(), Status> {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.state = peer.state.take().receive_last_state(last_state)?;
        }
        Ok(())
    }

    pub(crate) fn update_prove_request(
        &self,
        index: PeerIndex,
        request: ProveRequest,
    ) -> Result<(), Status> {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            let now = unix_time_as_millis();
            peer.state = peer.state.take().request_last_state_proof(request, now)?;
        }
        Ok(())
    }

    pub(crate) fn update_prove_state(
        &self,
        index: PeerIndex,
        state: ProveState,
    ) -> Result<(), Status> {
        *self.last_headers.write().expect("poisoned") = state.get_last_headers().to_vec();
        if let Some(mut peer) = self.inner.get_mut(&index) {
            let has_reorg = !state.reorg_last_headers.is_empty();
            peer.state = peer.state.take().receive_last_state_proof(state)?;
            if has_reorg {
                peer.latest_block_filter_hashes.clear();
            }
        }
        Ok(())
    }

    pub(crate) fn add_block(
        &self,
        matched_blocks: &mut HashMap<H256, (bool, Option<packed::Block>)>,
        block: packed::Block,
    ) -> Option<bool> {
        let block_hash = block.header().calc_header_hash();
        for mut pair in self.inner.iter_mut() {
            pair.value_mut().add_block(&block_hash);
        }
        matched_blocks.get_mut(&block_hash.unpack()).map(|value| {
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
            if let Some(value) = matched_blocks.get_mut(&block_hash.unpack()) {
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
            let peer = &pair.value();
            if let Some(req) = peer.get_blocks_proof_request() {
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
            let peer = &pair.value();
            if let Some(req) = peer.get_blocks_request() {
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
        should_get_blocks: bool,
    ) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.blocks_proof_request = request.map(|content| {
                BlocksProofRequest::new(content, unix_time_as_millis(), should_get_blocks)
            });
        }
    }
    pub(crate) fn update_blocks_request(&self, index: PeerIndex, hashes: Option<Vec<Byte32>>) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.blocks_request =
                hashes.map(|hashes| BlocksRequest::new(hashes, unix_time_as_millis()));
        }
    }
    pub(crate) fn update_txs_proof_request(
        &self,
        index: PeerIndex,
        request: Option<packed::GetTransactionsProof>,
    ) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.txs_proof_request = request
                .map(|content| TransactionsProofRequest::new(content, unix_time_as_millis()));
        }
    }

    pub(crate) fn add_check_points(
        &self,
        index: PeerIndex,
        last_proved_number: BlockNumber,
        start_number: BlockNumber,
        check_points: &[packed::Byte32],
    ) -> Result<Option<BlockNumber>, Status> {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.check_points
                .add_check_points(last_proved_number, start_number, check_points)
        } else {
            Err(StatusCode::PeerIsNotFound.into())
        }
    }

    pub(crate) fn remove_first_n_check_points(&self, index: PeerIndex, n: usize) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.check_points.remove_first_n_check_points(n);
            let number = peer.check_points.number_of_first_check_point();
            peer.latest_block_filter_hashes.reset(number);
        }
    }

    #[cfg(test)]
    pub(crate) fn mock_latest_block_filter_hashes(
        &self,
        index: PeerIndex,
        check_point_number: BlockNumber,
        block_filter_hashes: Vec<packed::Byte32>,
    ) {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            peer.latest_block_filter_hashes =
                LatestBlockFilterHashes::mock(check_point_number, block_filter_hashes);
        }
    }

    #[allow(clippy::too_many_arguments)] // TODO fix clippy
    pub(crate) fn update_latest_block_filter_hashes(
        &self,
        index: PeerIndex,
        last_proved_number: BlockNumber,
        finalized_check_point_index: u32,
        finalized_check_point: &packed::Byte32,
        start_number: BlockNumber,
        parent_block_filter_hash: &packed::Byte32,
        block_filter_hashes: &[packed::Byte32],
    ) -> Result<Option<BlockNumber>, Status> {
        if let Some(mut peer) = self.inner.get_mut(&index) {
            let finalized_check_point_number =
                self.calc_check_point_number(finalized_check_point_index);
            peer.latest_block_filter_hashes
                .update_latest_block_filter_hashes(
                    last_proved_number,
                    finalized_check_point_number,
                    finalized_check_point,
                    start_number,
                    parent_block_filter_hash,
                    block_filter_hashes,
                )
        } else {
            Err(StatusCode::PeerIsNotFound.into())
        }
    }

    pub(crate) fn update_min_filtered_block_number(&self, min_filtered_block_number: BlockNumber) {
        let should_cached_check_point_index =
            self.calc_cached_check_point_index_when_sync_at(min_filtered_block_number + 1);
        let current_cached_check_point_index =
            self.cached_block_filter_hashes.read().expect("poisoned").0;
        if current_cached_check_point_index != should_cached_check_point_index {
            let mut tmp = self.cached_block_filter_hashes.write().expect("poisoned");
            tmp.0 = should_cached_check_point_index;
            tmp.1.clear();
        }
    }

    pub(crate) fn get_cached_block_filter_hashes(&self) -> (u32, Vec<packed::Byte32>) {
        self.cached_block_filter_hashes
            .read()
            .expect("poisoned")
            .clone()
    }

    pub(crate) fn update_cached_block_filter_hashes(&self, hashes: Vec<packed::Byte32>) {
        self.cached_block_filter_hashes.write().expect("poisoned").1 = hashes;
    }

    pub(crate) fn if_cached_block_filter_hashes_require_update(
        &self,
        finalized_check_point_index: u32,
    ) -> Option<BlockNumber> {
        let (cached_index, cached_length) = {
            let tmp = self.cached_block_filter_hashes.read().expect("poisoned");
            (tmp.0, tmp.1.len())
        };
        if cached_index >= finalized_check_point_index {
            return None;
        }
        if cached_length as BlockNumber >= self.check_point_interval {
            return None;
        }
        let cached_last_number =
            self.calc_check_point_number(cached_index) + cached_length as BlockNumber;
        Some(cached_last_number + 1)
    }

    pub(crate) fn get_peers_which_require_new_state(&self, before_ts: u64) -> Vec<PeerIndex> {
        self.inner
            .iter()
            .filter_map(|item| {
                let (peer_index, peer) = item.pair();
                if peer.state.require_new_last_state(before_ts) {
                    Some(*peer_index)
                } else {
                    None
                }
            })
            .collect()
    }

    pub(crate) fn get_peers_which_require_new_proof(&self) -> Vec<PeerIndex> {
        self.inner
            .iter()
            .filter_map(|item| {
                let (peer_index, peer) = item.pair();
                if peer.state.require_new_last_state_proof() {
                    Some(*peer_index)
                } else {
                    None
                }
            })
            .collect()
    }

    pub(crate) fn get_peers_which_require_more_check_points(
        &self,
    ) -> Vec<(PeerIndex, BlockNumber)> {
        self.inner
            .iter()
            .filter_map(|item| {
                let (peer_index, peer) = item.pair();
                peer.state.get_prove_state().and_then(|state| {
                    let proved_number = state.get_last_header().header().number();
                    let check_points = &item.value().check_points;
                    if check_points.if_require_next_check_point(proved_number) {
                        let next_check_point_number = check_points.number_of_next_check_point();
                        Some((*peer_index, next_check_point_number))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    pub(crate) fn get_peers_which_require_more_latest_block_filter_hashes(
        &self,
        finalized_check_point_index: u32,
    ) -> Vec<(PeerIndex, BlockNumber)> {
        self.inner
            .iter()
            .filter_map(|item| {
                let (peer_index, peer) = item.pair();
                peer.state.get_prove_state().and_then(|state| {
                    let latest_block_filter_hashes = &item.value().latest_block_filter_hashes;
                    let check_point_number = latest_block_filter_hashes.get_check_point_number();
                    let finalized_check_point_number =
                        self.calc_check_point_number(finalized_check_point_index);
                    if check_point_number == finalized_check_point_number {
                        let proved_number = state.get_last_header().header().number();
                        let last_number = latest_block_filter_hashes.get_last_number();
                        if last_number < proved_number
                            && proved_number - last_number < self.check_point_interval * 2
                        {
                            Some((*peer_index, last_number + 1))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    pub(crate) fn get_latest_block_filter_hashes(
        &self,
        finalized_check_point_index: u32,
    ) -> Vec<packed::Byte32> {
        let finalized_check_point_number =
            self.calc_check_point_number(finalized_check_point_index);
        let mut peers_with_data = self
            .inner
            .iter()
            .filter_map(|item| {
                let (peer_index, peer) = item.pair();
                peer.state.get_prove_state().and_then(|_| {
                    let latest_block_filter_hashes = &item.value().latest_block_filter_hashes;
                    let check_point_number = latest_block_filter_hashes.get_check_point_number();
                    if finalized_check_point_number == check_point_number {
                        Some((*peer_index, latest_block_filter_hashes.get_hashes()))
                    } else {
                        None
                    }
                })
            })
            .collect::<HashMap<_, _>>();
        let required_peers_count = self.required_peers_count();
        if peers_with_data.len() < required_peers_count {
            return Vec::new();
        }
        let length_max = {
            let mut hashes_sizes = peers_with_data
                .values()
                .map(|hashes| hashes.len())
                .collect::<Vec<_>>();
            hashes_sizes.sort();
            hashes_sizes[required_peers_count - 1]
        };
        let mut result = Vec::new();
        for index in 0..length_max {
            let map = peers_with_data
                .values()
                .map(|hashes| hashes.get(index))
                .fold(HashMap::new(), |mut map, hash_opt| {
                    if let Some(h) = hash_opt {
                        *map.entry(h.clone()).or_default() += 1;
                    }
                    map
                });
            let count_max = map.values().max().cloned().unwrap_or(0);
            if count_max >= required_peers_count {
                let hash_opt =
                    map.into_iter().find_map(
                        |(hash, count)| {
                            if count == count_max {
                                Some(hash)
                            } else {
                                None
                            }
                        },
                    );
                let hash = hash_opt.expect("checked: must be found");
                if count_max != peers_with_data.len() {
                    peers_with_data
                        .retain(|_, hashes| matches!(hashes.get(index), Some(tmp) if *tmp == hash));
                }
                result.push(hash);
            } else {
                break;
            }
        }
        result
    }

    pub(crate) fn could_request_more_block_filters(
        &self,
        finalized_check_point_index: u32,
        min_filtered_block_number: BlockNumber,
    ) -> bool {
        let should_cached_check_point_index =
            self.calc_cached_check_point_index_when_sync_at(min_filtered_block_number + 1);
        if should_cached_check_point_index >= finalized_check_point_index {
            let finalized_check_point_number =
                self.calc_check_point_number(finalized_check_point_index);
            let latest_block_filter_hashes_count = self
                .get_latest_block_filter_hashes(finalized_check_point_index)
                .len();
            finalized_check_point_number + latest_block_filter_hashes_count as BlockNumber
                >= min_filtered_block_number + 1
        } else {
            // Check:
            // - If cached block filter hashes is same check point as the required,
            // - If all block filter hashes in that check point are downloaded.
            let cached_data = self.get_cached_block_filter_hashes();
            let current_cached_check_point_index = cached_data.0;
            should_cached_check_point_index == current_cached_check_point_index
                && cached_data.1.len() as BlockNumber == self.check_point_interval
        }
    }

    pub(crate) fn get_peers_which_have_timeout(&self, now: u64) -> Vec<PeerIndex> {
        self.inner
            .iter()
            .filter_map(|item| {
                let (peer_index, peer) = item.pair();
                peer.state
                    .when_sent_request()
                    .and_then(|when_sent| {
                        if now > when_sent + MESSAGE_TIMEOUT {
                            Some(*peer_index)
                        } else {
                            None
                        }
                    })
                    .or_else(|| {
                        peer.state.get_last_state().and_then(|state| {
                            if now > state.update_ts + MESSAGE_TIMEOUT {
                                Some(*peer_index)
                            } else {
                                None
                            }
                        })
                    })
                    .or_else(|| {
                        peer.get_blocks_proof_request().and_then(|req| {
                            if now > req.when_sent + MESSAGE_TIMEOUT {
                                Some(*peer_index)
                            } else {
                                None
                            }
                        })
                    })
                    .or_else(|| {
                        peer.get_blocks_request().and_then(|req| {
                            if now > req.when_sent + MESSAGE_TIMEOUT {
                                Some(*peer_index)
                            } else {
                                None
                            }
                        })
                    })
                    .or_else(|| {
                        peer.get_txs_proof_request().and_then(|req| {
                            if now > req.when_sent + MESSAGE_TIMEOUT {
                                Some(*peer_index)
                            } else {
                                None
                            }
                        })
                    })
            })
            .collect()
    }

    pub(crate) fn get_all_proved_check_points(
        &self,
    ) -> HashMap<PeerIndex, (u32, Vec<packed::Byte32>)> {
        self.inner
            .iter()
            .filter_map(|item| {
                let (peer_index, peer) = item.pair();
                peer.state.get_prove_state().map(|_| {
                    let start_index = peer.check_points.get_start_index();
                    let check_points = peer.check_points.get_check_points();
                    (*peer_index, (start_index, check_points))
                })
            })
            .collect()
    }

    pub(crate) fn get_all_prove_states(&self) -> Vec<(PeerIndex, ProveState)> {
        self.inner
            .iter()
            .filter_map(|item| {
                let (peer_index, peer) = item.pair();
                peer.state
                    .get_prove_state()
                    .map(|state| (*peer_index, state.to_owned()))
            })
            .collect()
    }

    pub(crate) fn find_if_a_header_is_proved(
        &self,
        header: &VerifiableHeader,
    ) -> Option<(PeerIndex, ProveState)> {
        self.inner.iter().find_map(|item| {
            let (peer_index, peer) = item.pair();
            peer.state.get_prove_state().and_then(|prove_state| {
                if prove_state.is_same_as(header) {
                    Some((*peer_index, prove_state.clone()))
                } else {
                    None
                }
            })
        })
    }

    pub(crate) fn get_best_proved_peers(&self, best_tip: &packed::Header) -> Vec<PeerIndex> {
        self.get_all_prove_states()
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
