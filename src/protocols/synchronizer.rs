use ckb_network::{async_trait, bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex};
use ckb_types::{packed, prelude::*};
use log::{info, trace, warn};
use std::sync::Arc;

use super::BAD_MESSAGE_BAN_TIME;
use crate::storage::Storage;

pub(crate) struct SyncProtocol {
    storage: Storage,
}

impl SyncProtocol {
    pub fn new(storage: Storage) -> Self {
        Self { storage }
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
                self.storage.filter_block(reader.to_entity().block());
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
