use std::sync::Arc;

use ckb_network::{
    bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex, SupportProtocols,
};

use crate::protocols::{FilterProtocol, Peers, BAD_MESSAGE_BAN_TIME};

use super::super::verify::new_storage;
use super::mock_context::MockProtocolContext;

#[tokio::test]
async fn test_block_filter_malformed_message() {
    let nc = Arc::new(MockProtocolContext::new(SupportProtocols::Filter));
    let storage = new_storage("test-block-filter");
    let peers = Arc::new(Peers::default());
    let mut protocol = FilterProtocol::new(storage, peers);

    let peer_index = PeerIndex::new(3);
    let data = Bytes::from(vec![2, 3, 4, 5]);
    let nc_clone = Arc::clone(&nc) as Arc<dyn CKBProtocolContext + Sync>;
    protocol.received(nc_clone, peer_index, data).await;
    assert_eq!(
        nc.has_banned(peer_index).map(|(duration, _)| duration),
        Some(BAD_MESSAGE_BAN_TIME)
    );
}
