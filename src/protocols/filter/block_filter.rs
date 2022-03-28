use super::{components, BAD_MESSAGE_BAN_TIME};
use crate::protocols::{Status, StatusCode};
use ckb_network::{bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex};
use ckb_types::{
    core::{BlockNumber, HeaderView},
    packed,
    prelude::*,
};
use golomb_coded_set::GCSFilterReader;
use log::{debug, error, info, trace, warn};
use std::future::pending;
use std::io::Cursor;
use std::sync::RwLock;
use std::time::Instant;
use std::{collections::HashMap, sync::Arc, time::Duration};

const GET_BLOCK_FILTERS_TOKEN: u64 = 0;
const GET_BLOCK_FILTERS_TIMEOUT: Duration = Duration::from_secs(15);

// use same value as bip158
const GCS_P: u8 = 19;
// M = 1.497137 * 2^P
const GCS_M: u64 = 784930;

pub struct PendingGetBlockFiltersPeer {
    pub(crate) peer: Option<PeerIndex>,
    pub(crate) block_number: BlockNumber,
    pub(crate) scripts: Vec<packed::Script>,
    pub(crate) script_hashes: Vec<packed::Byte32>,
    pub(crate) last_ask_time: Option<Instant>,
}

impl PendingGetBlockFiltersPeer {
    pub fn check_filters_data(&self, block_filters: packed::BlockFilters) {
        let reader = GCSFilterReader::new(0, 0, GCS_M, GCS_P);
        for (index, block_filter) in block_filters.filters().into_iter().enumerate() {
            let mut input = Cursor::new(block_filter.as_slice());
            if reader
                .match_any(
                    &mut input,
                    &mut self.script_hashes.iter().map(|v| v.as_slice()),
                )
                .expect("GCSFilterReader#match_any should be ok")
            {
                // TODO: store the block_hash and ask for the block through the sync protocol
                info!(
                    "check_filters_data matched, block_hash: {:#x}",
                    block_filters.block_hashes().get(index).expect("msg")
                );
            } else {
                info!(
                    "check_filters_data not matched, block_hash: {:#x}",
                    block_filters.block_hashes().get(index).expect("msg")
                );
            }
        }
    }

    pub fn should_ask(&self) -> bool {
        (self.peer.is_some() && !self.script_hashes.is_empty())
            && (self.last_ask_time.is_none()
                || self.last_ask_time.unwrap().elapsed() > GET_BLOCK_FILTERS_TIMEOUT)
    }
}

pub struct FilterProtocol {
    pub(crate) pending_peer: RwLock<PendingGetBlockFiltersPeer>,
}

impl FilterProtocol {
    pub fn new() -> Self {
        // TODO: only support one peer in current POC code, need to support multiple peers fetching block filters in future
        Self {
            pending_peer: RwLock::new(PendingGetBlockFiltersPeer {
                peer: None,
                block_number: 0,
                scripts: vec![],
                script_hashes: vec![],
                last_ask_time: None,
            }),
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
        self.pending_peer.write().unwrap().peer = Some(peer);
    }

    fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex) {
        info!("FilterProtocol.disconnected peer={}", peer);
        self.pending_peer.write().unwrap().peer = None;
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
                let pending_peer = self
                    .pending_peer
                    .write()
                    .expect("accuire pending_peer write lock");
                if pending_peer.should_ask() {
                    let content = packed::GetBlockFilters::new_builder()
                        .start_number((pending_peer.block_number).pack())
                        .build();

                    let message = packed::BlockFilterMessage::new_builder()
                        .set(content)
                        .build();

                    if let Err(err) =
                        nc.send_message_to(pending_peer.peer.unwrap(), message.as_bytes())
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
