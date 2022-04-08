use ckb_network::{bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex};
use ckb_types::{packed, prelude::*};
use log::{info, trace, warn};
use std::sync::Arc;
use std::time::Duration;

pub const BAD_MESSAGE_BAN_TIME: Duration = Duration::from_secs(5 * 60);

pub(crate) struct SyncProtocol {}

impl SyncProtocol {
    pub fn new() -> Self {
        Self {}
    }
}

impl CKBProtocolHandler for SyncProtocol {
    fn init(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>) {}

    fn connected(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        version: &str,
    ) {
        info!("SyncProtocol({}).connected peer={}", version, peer);
    }

    fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex) {
        info!("SyncProtocol.disconnected peer={}", peer);
    }

    fn received(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex, data: Bytes) {
        trace!("SyncProtocol.received peer={}", peer);

        let message = match packed::SyncMessage::from_slice(&data) {
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
