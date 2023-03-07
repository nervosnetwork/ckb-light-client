use super::{components, BAD_MESSAGE_BAN_TIME};
use crate::protocols::{Peers, Status, StatusCode};
use crate::storage::Storage;
use crate::utils::network::prove_or_download_matched_blocks;
use ckb_constant::sync::INIT_BLOCKS_IN_TRANSIT_PER_PEER;
use ckb_network::{async_trait, bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex};
use ckb_types::{core::BlockNumber, packed, prelude::*};
use golomb_coded_set::{GCSFilterReader, SipHasher24Builder, M, P};
use log::{debug, error, info, log_enabled, trace, warn, Level};
use rand::seq::SliceRandom as _;
use std::io::Cursor;
use std::sync::RwLock;
use std::time::Instant;
use std::{sync::Arc, time::Duration};

pub(crate) const GET_BLOCK_FILTERS_TOKEN: u64 = 0;
pub(crate) const GET_BLOCK_FILTER_HASHES_TOKEN: u64 = 1;
pub(crate) const GET_BLOCK_FILTER_CHECK_POINTS_TOKEN: u64 = 2;

pub(crate) const GET_BLOCK_FILTERS_DURATION: Duration = Duration::from_secs(3);
pub(crate) const GET_BLOCK_FILTER_HASHES_DURATION: Duration = Duration::from_secs(10);
pub(crate) const GET_BLOCK_FILTER_CHECK_POINTS_DURATION: Duration = Duration::from_secs(30);

const GET_BLOCK_FILTERS_TIMEOUT: Duration = Duration::from_secs(15);

pub struct FilterProtocol {
    pub(crate) storage: Storage,
    pub(crate) peers: Arc<Peers>,
    pub(crate) last_ask_time: Arc<RwLock<Option<Instant>>>,
}

impl FilterProtocol {
    pub fn new(storage: Storage, peers: Arc<Peers>) -> Self {
        Self {
            storage,
            peers,
            last_ask_time: Arc::new(RwLock::new(None)),
        }
    }

    pub fn check_filters_data(
        &self,
        block_filters: packed::BlockFilters,
        limit: usize,
    ) -> Vec<packed::Byte32> {
        let start_number: BlockNumber = block_filters.start_number().unpack();
        let reader = GCSFilterReader::new(SipHasher24Builder::new(0, 0), M, P);
        let script_hashes = self
            .storage
            .get_scripts_hash(start_number + limit as BlockNumber);
        block_filters
            .filters()
            .into_iter()
            .take(limit)
            .enumerate()
            .filter_map(|(index, block_filter)| {
                let mut input = Cursor::new(block_filter.raw_data());
                if reader
                    .match_any(&mut input, &mut script_hashes.iter().map(|v| v.as_slice()))
                    .expect("GCSFilterReader#match_any should be ok")
                {
                    let block_hash = block_filters
                        .block_hashes()
                        .get(index)
                        .expect("checked index");
                    info!("check_filters_data matched, block_hash: {:#x}", block_hash);
                    Some(block_hash)
                } else {
                    trace!(
                        "check_filters_data not matched, block_hash: {:#x}",
                        block_filters.block_hashes().get(index).expect("msg")
                    );
                    None
                }
            })
            .collect()
    }

    fn should_ask(&self, immediately: bool) -> bool {
        !self.storage.is_filter_scripts_empty()
            && (immediately
                || self.last_ask_time.read().unwrap().is_none()
                || self.last_ask_time.read().unwrap().unwrap().elapsed()
                    > GET_BLOCK_FILTERS_TIMEOUT)
    }

    pub fn update_min_filtered_block_number(&self, block_number: BlockNumber) {
        self.storage.update_min_filtered_block_number(block_number);
        self.peers.update_min_filtered_block_number(block_number);
        self.last_ask_time.write().unwrap().replace(Instant::now());
    }

    pub(crate) fn try_send_get_block_filters(
        &self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        immediately: bool,
    ) {
        let start_number = self.storage.get_min_filtered_block_number() + 1;
        let (finalized_check_point_index, _) = self.storage.get_last_check_point();
        let could_ask_more = self
            .peers
            .could_request_more_block_filters(finalized_check_point_index, start_number);
        if log_enabled!(Level::Trace) {
            let finalized_check_point_number = self
                .peers
                .calc_check_point_number(finalized_check_point_index);
            let (cached_check_point_index, cached_hashes) =
                self.peers.get_cached_block_filter_hashes();
            let cached_check_point_number =
                self.peers.calc_check_point_number(cached_check_point_index);
            let next_cached_check_point_number = self
                .peers
                .calc_check_point_number(cached_check_point_index + 1);
            trace!(
                "could request block filters from {} or not: {}, \
                         finalized: index {}, number {}; \
                         cached: index {}, number {}, length {}; \
                         next cached: number {}",
                start_number,
                could_ask_more,
                finalized_check_point_index,
                finalized_check_point_number,
                cached_check_point_index,
                cached_check_point_number,
                cached_hashes.len(),
                next_cached_check_point_number
            );
        }
        if let Some((peer, _prove_state)) = self
            .peers
            .get_all_prove_states()
            .iter()
            .max_by_key(|(_, prove_state)| prove_state.get_last_header().total_difficulty())
        {
            debug!("found best proved peer {}", peer);

            let mut matched_blocks = self.peers.matched_blocks().write().expect("poisoned");
            if let Some((db_start_number, blocks_count, db_blocks)) =
                self.storage.get_earliest_matched_blocks()
            {
                debug!(
                    "try recover matched blocks from storage, start_number={}, \
                             blocks_count={}, matched_count: {}",
                    db_start_number,
                    blocks_count,
                    matched_blocks.len(),
                );
                if matched_blocks.is_empty() {
                    // recover matched blocks from storage
                    self.peers
                        .add_matched_blocks(&mut matched_blocks, db_blocks);
                    let tip_header = self.storage.get_tip_header();
                    prove_or_download_matched_blocks(
                        Arc::clone(&self.peers),
                        &tip_header,
                        &matched_blocks,
                        nc.as_ref(),
                        INIT_BLOCKS_IN_TRANSIT_PER_PEER,
                    );
                    if could_ask_more {
                        debug!(
                            "send get block filters to {}, start_number={}",
                            peer, start_number
                        );
                        self.send_get_block_filters(nc, *peer, start_number);
                    }
                }
            } else if self.should_ask(immediately) && could_ask_more {
                debug!(
                    "send get block filters to {}, start_number={}",
                    peer, start_number
                );
                self.send_get_block_filters(nc, *peer, start_number);
            } else {
                trace!("no block filters is required to download");
            }
        } else {
            debug!("cannot find peers which are proved");
        }
    }

    pub(crate) fn try_send_get_block_filter_hashes(&self, nc: Arc<dyn CKBProtocolContext + Sync>) {
        let min_filtered_block_number = self.storage.get_min_filtered_block_number();
        self.peers
            .update_min_filtered_block_number(min_filtered_block_number);
        let finalized_check_point_index = self.storage.get_max_check_point_index();
        let cached_check_point_index = self.peers.get_cached_block_filter_hashes().0;
        if let Some(start_number) = self
            .peers
            .if_cached_block_filter_hashes_require_update(finalized_check_point_index)
        {
            let best_peers = self
                .peers
                .get_all_proved_check_points()
                .into_iter()
                .filter_map(|(peer_index, (cpindex, _check_points))| {
                    if cpindex >= finalized_check_point_index {
                        Some(peer_index)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            if let Some(peer) = best_peers.choose(&mut rand::thread_rng()).cloned() {
                self.send_get_block_filter_hashes(Arc::clone(&nc), peer, start_number);
            }
        } else if cached_check_point_index >= finalized_check_point_index {
            let peers = self
                .peers
                .get_peers_which_require_more_latest_block_filter_hashes(
                    finalized_check_point_index,
                );
            for (peer, start_number) in peers {
                self.send_get_block_filter_hashes(Arc::clone(&nc), peer, start_number);
            }
        }
    }
}

impl FilterProtocol {
    fn try_process(
        &self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        message: packed::BlockFilterMessageUnionReader<'_>,
    ) -> Status {
        match message {
            packed::BlockFilterMessageUnionReader::BlockFilterCheckPoints(reader) => {
                components::BlockFilterCheckPointsProcess::new(reader, self, nc, peer).execute()
            }
            packed::BlockFilterMessageUnionReader::BlockFilterHashes(reader) => {
                components::BlockFilterHashesProcess::new(reader, self, nc, peer).execute()
            }
            packed::BlockFilterMessageUnionReader::BlockFilters(reader) => {
                components::BlockFiltersProcess::new(reader, self, nc, peer).execute()
            }
            _ => StatusCode::UnexpectedProtocolMessage.into(),
        }
    }

    pub(crate) fn send_get_block_filters(
        &self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        start_number: BlockNumber,
    ) {
        trace!(
            "request block filter from peer {}, starts at {}",
            peer,
            start_number
        );
        let content = packed::GetBlockFilters::new_builder()
            .start_number(start_number.pack())
            .build();
        let message = packed::BlockFilterMessage::new_builder()
            .set(content)
            .build();
        if let Err(err) = nc.send_message_to(peer, message.as_bytes()) {
            let error_message = format!("nc.send_message GetBlockFilters, error: {:?}", err);
            error!("{}", error_message);
        }
    }

    pub(crate) fn send_get_block_filter_hashes(
        &self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        start_number: BlockNumber,
    ) {
        trace!(
            "request block filter hashes from peer {}, starts at {}",
            peer,
            start_number
        );
        let content = packed::GetBlockFilterHashes::new_builder()
            .start_number(start_number.pack())
            .build();
        let message = packed::BlockFilterMessage::new_builder()
            .set(content)
            .build();
        if let Err(err) = nc.send_message_to(peer, message.as_bytes()) {
            let error_message = format!("nc.send_message GetBlockFilterHashes, error: {:?}", err);
            error!("{}", error_message);
        }
    }

    pub(crate) fn send_get_block_filter_check_points(
        &self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        start_number: BlockNumber,
    ) {
        trace!(
            "request check points from peer {}, starts at {}",
            peer,
            start_number
        );
        let content = packed::GetBlockFilterCheckPoints::new_builder()
            .start_number(start_number.pack())
            .build();
        let message = packed::BlockFilterMessage::new_builder()
            .set(content)
            .build();
        if let Err(err) = nc.send_message_to(peer, message.as_bytes()) {
            let error_message = format!(
                "nc.send_message GetBlockFilterCheckPoints, error: {:?}",
                err
            );
            error!("{}", error_message);
        }
    }
}

#[async_trait]
impl CKBProtocolHandler for FilterProtocol {
    async fn init(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>) {
        nc.set_notify(GET_BLOCK_FILTERS_DURATION, GET_BLOCK_FILTERS_TOKEN)
            .await
            .expect("set_notify should be ok");
        nc.set_notify(
            GET_BLOCK_FILTER_HASHES_DURATION,
            GET_BLOCK_FILTER_HASHES_TOKEN,
        )
        .await
        .expect("set_notify should be ok");
        nc.set_notify(
            GET_BLOCK_FILTER_CHECK_POINTS_DURATION,
            GET_BLOCK_FILTER_CHECK_POINTS_TOKEN,
        )
        .await
        .expect("set_notify should be ok");
    }

    async fn connected(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        version: &str,
    ) {
        debug!("FilterProtocol({}).connected peer={}", version, peer);
    }

    async fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex) {
        debug!("FilterProtocol.disconnected peer={}", peer);
    }

    async fn received(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        data: Bytes,
    ) {
        let msg = match packed::BlockFilterMessageReader::from_slice(&data) {
            Ok(msg) => msg.to_enum(),
            _ => {
                warn!(
                    "FilterProtocol.received a malformed message from Peer({})",
                    peer
                );
                nc.ban_peer(
                    peer,
                    BAD_MESSAGE_BAN_TIME,
                    String::from("send us a malformed message"),
                );
                return;
            }
        };

        let item_name = msg.item_name();
        let status = self.try_process(Arc::clone(&nc), peer, msg);
        status.process(nc, peer, "BlockFilter", item_name);
    }

    async fn notify(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>, token: u64) {
        match token {
            GET_BLOCK_FILTERS_TOKEN => {
                self.try_send_get_block_filters(nc, false);
            }
            GET_BLOCK_FILTER_HASHES_TOKEN => {
                self.try_send_get_block_filter_hashes(nc);
            }
            GET_BLOCK_FILTER_CHECK_POINTS_TOKEN => {
                let peers = self.peers.get_peers_which_require_more_check_points();
                for (peer, start_number) in peers {
                    self.send_get_block_filter_check_points(Arc::clone(&nc), peer, start_number);
                }
            }
            _ => unreachable!(),
        }
    }
}
