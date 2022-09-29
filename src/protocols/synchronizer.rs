use ckb_network::{
    async_trait, bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex, SupportProtocols,
};
use ckb_types::{packed, prelude::*};
use log::{error, info, trace, warn};
use std::collections::HashSet;
use std::sync::Arc;

use super::BAD_MESSAGE_BAN_TIME;
use crate::protocols::Peers;
use crate::storage::Storage;

pub(crate) struct SyncProtocol {
    storage: Storage,
    peers: Arc<Peers>,
}

impl SyncProtocol {
    pub fn new(storage: Storage, peers: Arc<Peers>) -> Self {
        Self { storage, peers }
    }
}

#[async_trait]
impl CKBProtocolHandler for SyncProtocol {
    async fn init(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>) {}

    async fn connected(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        version: &str,
    ) {
        info!("SyncProtocol({}).connected peer={}", version, peer);
    }

    async fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex) {
        info!("SyncProtocol.disconnected peer={}", peer);
    }

    async fn received(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        data: Bytes,
    ) {
        let message = match packed::SyncMessageReader::from_compatible_slice(&data) {
            Ok(msg) => msg.to_enum(),
            _ => {
                warn!(
                    "SyncProtocol.received a malformed message from Peer({})",
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

        trace!(
            "SyncProtocol.received peer={}, message={}",
            peer,
            message.item_name()
        );
        match message {
            packed::SyncMessageUnionReader::SendBlock(reader) => {
                let new_block = reader.to_entity().block();
                let mut matched_blocks = self.peers.matched_blocks().write().expect("poisoned");
                self.peers.add_block(&mut matched_blocks, new_block);

                if self.peers.all_matched_blocks_downloaded(&matched_blocks) {
                    let (start_number, blocks_count, db_blocks) = self
                        .storage
                        .get_matched_blocks()
                        .expect("get matched blocks from storage");
                    let db_blocks: HashSet<_> =
                        db_blocks.into_iter().map(|(hash, _)| hash).collect();

                    // NOTE must remove matched blocks in storage first
                    self.storage.remove_matched_blocks();
                    let blocks = self.peers.clear_matched_blocks(&mut matched_blocks);
                    assert_eq!(blocks.len(), db_blocks.len());
                    info!(
                        "all matched blocks downloaded, start_number={}, blocks_count={}, matched_count={}",
                        start_number,
                        blocks_count,
                        db_blocks.len()
                    );

                    // update storage
                    for block in blocks {
                        assert!(db_blocks.contains(&block.header().calc_header_hash()));
                        self.storage.filter_block(block);
                    }
                    let filtered_block_number = start_number - 1 + blocks_count;
                    self.storage.update_block_number(filtered_block_number);

                    // send next GetBlockFilters message
                    let content = packed::GetBlockFilters::new_builder()
                        .start_number((filtered_block_number + 1).pack())
                        .build();
                    let message = packed::BlockFilterMessage::new_builder()
                        .set(content)
                        .build()
                        .as_bytes();
                    if let Err(err) =
                        nc.send_message(SupportProtocols::Filter.protocol_id(), peer, message)
                    {
                        let error_message =
                            format!("nc.send_message BlockFilterMessage, error: {:?}", err);
                        error!("{}", error_message);
                    }
                }
            }
            _ => {
                let content = packed::InIBD::new_builder().build();
                let msg = packed::SyncMessage::new_builder().set(content).build();
                if let Err(err) = nc.send_message_to(peer, msg.as_bytes()) {
                    warn!(
                        "SyncProtocol.received failed to send InIBD message to peer={} since {:?}",
                        peer, err
                    );
                }
            }
        }
    }
}
