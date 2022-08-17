use std::sync::Arc;

use ckb_network::{
    bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex, SupportProtocols,
};
use ckb_types::{
    core::{EpochNumberWithFraction, HeaderBuilder},
    packed::{self, Script},
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
    U256,
};

use crate::protocols::{
    FilterProtocol, LastState, Peers, ProveRequest, ProveState, BAD_MESSAGE_BAN_TIME,
    GET_BLOCK_FILTERS_TOKEN,
};

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

#[tokio::test]
async fn test_block_filter_ignore_start_number() {}

#[tokio::test]
async fn test_block_filter_empty_filters() {}

#[tokio::test]
async fn test_block_filter_start_number_too_big() {}

#[tokio::test]
async fn test_block_filter_blocks_matched() {}

#[tokio::test]
async fn test_block_filter_notify_ask_filters() {
    let nc = Arc::new(MockProtocolContext::new(SupportProtocols::Filter));
    let min_filtered_block_number = 3;
    let storage = {
        let storage = new_storage("test-block-filter");
        storage.update_filter_scripts(
            vec![(Script::default(), min_filtered_block_number)]
                .into_iter()
                .collect(),
        );
        storage
    };

    let peer_index = PeerIndex::new(3);
    let peers = {
        let tip_header = VerifiableHeader::new(
            HeaderBuilder::default()
                .epoch(EpochNumberWithFraction::new(0, 0, 100).full_value().pack())
                .number(5u64.pack())
                .build(),
            Default::default(),
            None,
        );
        let last_state = LastState {
            tip_header,
            total_difficulty: U256::one(),
        };
        let request = ProveRequest::new(last_state, Default::default());
        let prove_state =
            ProveState::new_from_request(request, Default::default(), Default::default());
        let peers = Arc::new(Peers::default());
        peers.add_peer(peer_index);
        peers.commit_prove_state(peer_index, prove_state);
        peers
    };
    let mut protocol = FilterProtocol::new(storage, peers);

    let nc_clone = Arc::clone(&nc) as Arc<dyn CKBProtocolContext + Sync>;
    protocol.notify(nc_clone, GET_BLOCK_FILTERS_TOKEN).await;
    let message = {
        let start_number: u64 = min_filtered_block_number + 1;
        let content = packed::GetBlockFilters::new_builder()
            .start_number(start_number.pack())
            .build();
        packed::BlockFilterMessage::new_builder()
            .set(content)
            .build()
    };
    assert!(nc.has_sent(
        SupportProtocols::Filter.protocol_id(),
        peer_index,
        message.as_bytes(),
    ));
}

#[tokio::test]
async fn test_block_filter_notify_no_proved_peers() {}

#[tokio::test]
async fn test_block_filter_notify_not_reach_ask() {}

#[tokio::test]
async fn test_block_filter_notify_not_reach_number() {}
