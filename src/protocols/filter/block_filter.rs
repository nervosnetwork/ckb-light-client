use super::{components, BAD_MESSAGE_BAN_TIME};
use crate::protocols::{Status, StatusCode};
use ckb_network::{bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex};
use ckb_types::{core::BlockNumber, packed, prelude::*};
use golomb_coded_set::GCSFilterReader;
use log::{debug, error, info, trace, warn};
use std::io::Cursor;
use std::sync::RwLock;
use std::time::Instant;
use std::{sync::Arc, time::Duration};

const GET_BLOCK_FILTERS_TOKEN: u64 = 0;
const GET_BLOCK_FILTERS_TIMEOUT: Duration = Duration::from_secs(15);

// use same value as bip158
const GCS_P: u8 = 19;
// M = 1.497137 * 2^P
const GCS_M: u64 = 784930;

pub struct PendingGetBlockFiltersPeer {
    pub(crate) peer: Option<PeerIndex>,
    pub(crate) script_hashes_and_block_number: Arc<RwLock<(Vec<packed::Byte32>, BlockNumber)>>,
    pub(crate) last_ask_time: Arc<RwLock<Option<Instant>>>,
}

impl PendingGetBlockFiltersPeer {
    pub fn check_filters_data(&self, block_filters: packed::BlockFilters) {
        let reader = GCSFilterReader::new(0, 0, GCS_M, GCS_P);
        let script_hashes = &self.script_hashes_and_block_number.read().unwrap().0;
        for (index, block_filter) in block_filters.filters().into_iter().enumerate() {
            let mut input = Cursor::new(block_filter.raw_data());
            if reader
                .match_any(&mut input, &mut script_hashes.iter().map(|v| v.as_slice()))
                .expect("GCSFilterReader#match_any should be ok")
            {
                // TODO: store the block_hash and ask for the block through the sync protocol
                info!(
                    "check_filters_data matched, block_hash: {:#x}",
                    block_filters.block_hashes().get(index).expect("msg")
                );
            } else {
                trace!(
                    "check_filters_data not matched, block_hash: {:#x}",
                    block_filters.block_hashes().get(index).expect("msg")
                );
            }
        }
    }

    pub fn should_ask(&self) -> bool {
        (self.peer.is_some()
            && !self
                .script_hashes_and_block_number
                .read()
                .unwrap()
                .0
                .is_empty())
            && (self.last_ask_time.read().unwrap().is_none()
                || self.last_ask_time.read().unwrap().unwrap().elapsed()
                    > GET_BLOCK_FILTERS_TIMEOUT)
    }

    pub fn block_number(&self) -> BlockNumber {
        self.script_hashes_and_block_number.read().unwrap().1
    }

    pub fn update_block_number(&self, block_number: BlockNumber) {
        self.script_hashes_and_block_number.write().unwrap().1 = block_number;

        self.last_ask_time.write().unwrap().replace(Instant::now());
    }
}

pub struct FilterProtocol {
    pub(crate) pending_peer: PendingGetBlockFiltersPeer,
}

impl FilterProtocol {
    pub fn new(
        script_hashes_and_block_number: Arc<RwLock<(Vec<packed::Byte32>, BlockNumber)>>,
    ) -> Self {
        // TODO: only support one peer in current POC code, need to support multiple peers fetching block filters in future
        Self {
            pending_peer: PendingGetBlockFiltersPeer {
                peer: None,
                script_hashes_and_block_number,
                last_ask_time: Arc::new(RwLock::new(None)),
            },
        }
    }
}

impl FilterProtocol {
    fn try_process(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        message: packed::BlockFilterMessageUnionReader<'_>,
    ) -> Status {
        match message {
            // TODO: implement check points message processing
            packed::BlockFilterMessageUnionReader::BlockFilters(reader) => {
                components::BlockFiltersProcess::new(reader, &self, nc, peer).execute()
            }
            _ => StatusCode::UnexpectedProtocolMessage.into(),
        }
    }
}

impl CKBProtocolHandler for FilterProtocol {
    fn init(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>) {
        nc.set_notify(Duration::from_secs(3), GET_BLOCK_FILTERS_TOKEN)
            .expect("set_notify should be ok");
    }

    fn connected(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        version: &str,
    ) {
        info!("FilterProtocol({}).connected peer={}", version, peer);
        self.pending_peer.peer = Some(peer);
    }

    fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex) {
        info!("FilterProtocol.disconnected peer={}", peer);
        self.pending_peer.peer = None;
    }

    fn received(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex, data: Bytes) {
        trace!("FilterProtocol.received peer={}", peer);

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

    fn notify(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>, token: u64) {
        match token {
            GET_BLOCK_FILTERS_TOKEN => {
                if self.pending_peer.should_ask() {
                    let content = packed::GetBlockFilters::new_builder()
                        .start_number(
                            (self
                                .pending_peer
                                .script_hashes_and_block_number
                                .read()
                                .unwrap()
                                .1)
                                .pack(),
                        )
                        .build();

                    let message = packed::BlockFilterMessage::new_builder()
                        .set(content)
                        .build();

                    if let Err(err) =
                        nc.send_message_to(self.pending_peer.peer.unwrap(), message.as_bytes())
                    {
                        let error_message =
                            format!("nc.send_message BlockFilterMessage, error: {:?}", err);
                        error!("{}", error_message);
                    }
                }
            }
            _ => unreachable!(),
        }
    }
}
