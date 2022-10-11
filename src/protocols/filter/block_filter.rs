use super::{components, BAD_MESSAGE_BAN_TIME};
use crate::protocols::{Peers, Status, StatusCode};
use crate::storage::Storage;
use crate::utils::network::prove_or_download_matched_blocks;
use ckb_constant::sync::INIT_BLOCKS_IN_TRANSIT_PER_PEER;
use ckb_network::{async_trait, bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex};
use ckb_types::{core::BlockNumber, packed, prelude::*};
use golomb_coded_set::{GCSFilterReader, SipHasher24Builder, M, P};
use log::{debug, error, info, trace, warn};
use std::io::Cursor;
use std::sync::RwLock;
use std::time::Instant;
use std::{sync::Arc, time::Duration};

pub(crate) const GET_BLOCK_FILTERS_TOKEN: u64 = 0;
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

    fn should_ask(&self) -> bool {
        !self.storage.get_filter_scripts().is_empty()
            && (self.last_ask_time.read().unwrap().is_none()
                || self.last_ask_time.read().unwrap().unwrap().elapsed()
                    > GET_BLOCK_FILTERS_TIMEOUT)
    }

    pub fn min_filtered_block_number(&self) -> BlockNumber {
        self.storage.get_min_filtered_block_number()
    }

    pub fn update_min_filtered_block_number(&self, block_number: BlockNumber) {
        self.storage.update_min_filtered_block_number(block_number);
        self.last_ask_time.write().unwrap().replace(Instant::now());
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
            // TODO: implement check points message processing
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
        start_number: u64,
    ) {
        let content = packed::GetBlockFilters::new_builder()
            .start_number(start_number.pack())
            .build();
        let message = packed::BlockFilterMessage::new_builder()
            .set(content)
            .build();
        if let Err(err) = nc.send_message_to(peer, message.as_bytes()) {
            let error_message = format!("nc.send_message BlockFilterMessage, error: {:?}", err);
            error!("{}", error_message);
        }
    }
}

#[async_trait]
impl CKBProtocolHandler for FilterProtocol {
    async fn init(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>) {
        nc.set_notify(Duration::from_secs(3), GET_BLOCK_FILTERS_TOKEN)
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
        trace!(
            "FilterProtocol.received peer={}, message={}",
            peer,
            item_name
        );
        if let Some(ban_time) = status.should_ban() {
            error!(
                "process {} from {}, ban {:?} since result is {}",
                item_name, peer, ban_time, status
            );
            nc.ban_peer(peer, ban_time, status.to_string());
        } else if status.should_warn() {
            warn!("process {} from {}, result is {}", item_name, peer, status);
        } else if !status.is_ok() {
            debug!("process {} from {}, result is {}", item_name, peer, status);
        }
    }

    async fn notify(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>, token: u64) {
        match token {
            GET_BLOCK_FILTERS_TOKEN => {
                let proved_peers = self.peers.get_peers_which_are_proved();
                if let Some((peer, prove_state)) = proved_peers
                    .iter()
                    .max_by_key(|(_, prove_state)| prove_state.get_last_header().total_difficulty())
                {
                    let start_number = self.min_filtered_block_number() + 1;
                    let prove_state_number = prove_state.get_last_header().header().number();
                    debug!(
                        "found proved peer {}, start_number: {}, prove_state number: {:?}",
                        peer,
                        start_number,
                        prove_state.get_last_header().header().number()
                    );

                    let mut matched_blocks = self.peers.matched_blocks().write().expect("poisoned");
                    if let Some((db_start_number, blocks_count, db_blocks)) =
                        self.storage.get_earliest_matched_blocks()
                    {
                        if matched_blocks.is_empty() {
                            debug!(
                                "recover matched blocks from storage, start_number={}, blocks_count={}, matched_count: {}",
                                db_start_number, blocks_count,
                                matched_blocks.len(),
                            );
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
                            if prove_state_number >= start_number {
                                debug!(
                                    "send get block filters to {}, start_number={}",
                                    peer, start_number
                                );
                                self.send_get_block_filters(Arc::clone(&nc), *peer, start_number);
                            }
                        }
                    } else if self.should_ask() && prove_state_number >= start_number {
                        debug!(
                            "send get block filters to {}, start_number={}",
                            peer, start_number
                        );
                        self.send_get_block_filters(Arc::clone(&nc), *peer, start_number);
                    }
                } else {
                    debug!("cannot find peers which are proved");
                }
            }
            _ => unreachable!(),
        }
    }
}
