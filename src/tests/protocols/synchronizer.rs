use std::collections::HashMap;
use std::sync::Arc;

use ckb_network::{CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_types::{
    core::BlockBuilder,
    packed::{self, Script},
    prelude::*,
};

use crate::{
    protocols::Peers,
    tests::{
        prelude::*,
        utils::{MockChain, MockNetworkContext},
    },
};

#[tokio::test]
async fn test_sync_add_block() {
    let chain = MockChain::new_with_dummy_pow("test-sync");
    let nc = MockNetworkContext::new(SupportProtocols::Sync);

    let mut scripts = HashMap::new();
    scripts.insert(Script::default(), 1);
    chain.client_storage().update_filter_scripts(scripts);

    let min_filtered_block_number = chain
        .client_storage()
        .get_filter_scripts()
        .values()
        .min()
        .cloned()
        .unwrap_or_default();
    let start_number = min_filtered_block_number + 1;
    let blocks_count = 1;
    let block_view = BlockBuilder::default().build();
    let proved_block_hash = block_view.hash();
    chain.client_storage().add_matched_blocks(
        start_number,
        blocks_count,
        vec![(proved_block_hash.clone(), true)],
    );
    let peer_index = PeerIndex::new(3);
    let peers = {
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        {
            let mut matched_blocks = peers.matched_blocks().write().unwrap();
            peers.add_matched_blocks(&mut matched_blocks, vec![(proved_block_hash, true)]);
        }
        peers
    };

    let message = {
        let content = packed::SendBlock::new_builder()
            .block(block_view.data())
            .build();
        packed::SyncMessage::new_builder()
            .set(content)
            .build()
            .as_bytes()
    };

    let mut protocol = chain.create_sync_protocol(Arc::clone(&peers));
    protocol.received(nc.context(), peer_index, message).await;

    assert!(peers.matched_blocks().read().unwrap().is_empty());
    assert!(chain
        .client_storage()
        .get_earliest_matched_blocks()
        .is_none());
    assert!(nc.not_banned(peer_index));
    let storage_filtered_block_number = chain
        .client_storage()
        .get_filter_scripts()
        .values()
        .min()
        .cloned()
        .unwrap_or_default();
    let filtered_block_number = start_number - 1 + blocks_count;
    assert_eq!(storage_filtered_block_number, filtered_block_number);
    assert!(nc.sent_messages().borrow().is_empty());
}
