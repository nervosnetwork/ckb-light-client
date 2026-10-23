use std::sync::Arc;

use ckb_constant::sync::INIT_BLOCKS_IN_TRANSIT_PER_PEER;
use ckb_network::{
    async_trait, bytes::Bytes, BoxedCKBProtocolContext, CKBProtocolHandler, PeerIndex,
};
use ckb_types::{core::BlockView, packed, prelude::*};
use log::{info, trace, warn};

use super::BAD_MESSAGE_BAN_TIME;
use crate::protocols::Peers;
use crate::storage::{LightClientStorage, Storage};
use crate::utils::network::prove_or_download_matched_blocks;

pub struct SyncProtocol {
    storage: Storage,
    peers: Arc<Peers>,
}

fn block_body_matches_header(block: &BlockView) -> bool {
    block.transactions_root() == block.calc_transactions_root()
        && block.proposals_hash() == block.calc_proposals_hash()
        && block.extra_hash() == block.calc_extra_hash().extra_hash()
        && block
            .uncles()
            .into_iter()
            .all(|uncle| uncle.proposals_hash() == uncle.calc_proposals_hash())
}

impl SyncProtocol {
    pub fn new(storage: Storage, peers: Arc<Peers>) -> Self {
        Self { storage, peers }
    }
}

#[async_trait]
impl CKBProtocolHandler for SyncProtocol {
    async fn init(&mut self, _nc: BoxedCKBProtocolContext) {}

    async fn connected(&mut self, _nc: BoxedCKBProtocolContext, peer: PeerIndex, version: &str) {
        info!("SyncProtocol({}).connected peer={}", version, peer);
    }

    async fn disconnected(&mut self, _nc: BoxedCKBProtocolContext, peer: PeerIndex) {
        info!("SyncProtocol.disconnected peer={}", peer);
    }

    async fn received(&mut self, nc: BoxedCKBProtocolContext, peer: PeerIndex, data: Bytes) {
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
                let block_hash = new_block.header().calc_header_hash();
                let block_hash_key = block_hash.unpack();
                let mut body_validated = false;
                // The proof state can change after releasing the read lock. Recheck it
                // under the write lock and validate before caching if it became proved.
                let mut matched_blocks = loop {
                    let should_validate = self
                        .peers
                        .matched_blocks()
                        .read()
                        .await
                        .get(&block_hash_key)
                        .is_some_and(|(proved, _)| *proved);
                    if should_validate && !body_validated {
                        let block = new_block.clone().into_view_without_reset_header();
                        if !block_body_matches_header(&block) {
                            warn!(
                                "SyncProtocol received a block whose body does not match \
                                 the proved header from peer={}",
                                peer
                            );
                            nc.ban_peer(
                                peer,
                                BAD_MESSAGE_BAN_TIME,
                                String::from("block body does not match header"),
                            );
                            return;
                        }
                        body_validated = true;
                    }

                    let matched_blocks = self.peers.matched_blocks().write().await;
                    let is_proved = matched_blocks
                        .get(&block_hash_key)
                        .is_some_and(|(proved, _)| *proved);
                    if is_proved && !body_validated {
                        drop(matched_blocks);
                        continue;
                    }
                    break matched_blocks;
                };
                self.peers.add_block(&mut matched_blocks, new_block);
                if let Err(error) = crate::utils::network::index_downloaded_blocks(
                    &self.storage,
                    &self.peers,
                    &mut matched_blocks,
                ) {
                    warn!("watched indexing paused: {error}");
                }
                let tip_header = self.storage.get_tip_header();
                prove_or_download_matched_blocks(
                    Arc::clone(&self.peers),
                    &tip_header,
                    &matched_blocks,
                    nc.as_ref(),
                    INIT_BLOCKS_IN_TRANSIT_PER_PEER,
                );
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
