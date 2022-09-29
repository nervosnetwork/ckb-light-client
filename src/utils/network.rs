use crate::protocols::{Peers, GET_BLOCKS_PROOF_LIMIT};
use ckb_constant::sync::INIT_BLOCKS_IN_TRANSIT_PER_PEER;
use ckb_network::{CKBProtocolContext, PeerIndex, SupportProtocols};
use ckb_types::{packed, prelude::*, H256};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) fn prove_or_download_matched_blocks(
    peers: Arc<Peers>,
    matched_blocks: &HashMap<H256, (bool, Option<packed::Block>)>,
    peer: PeerIndex,
    nc: &dyn CKBProtocolContext,
) {
    let peer_state = if let Some(peer_state) = peers.get_state(&peer) {
        peer_state
    } else {
        info!("ignoring, peer {} is disconnected", peer);
        return;
    };
    if peer_state.get_blocks_proof_request().is_some() {
        info!("peer {} has an inflight GetBlocksProof request", peer);
    } else {
        let blocks_to_prove =
            peers.get_matched_blocks_to_prove(matched_blocks, GET_BLOCKS_PROOF_LIMIT);
        if !blocks_to_prove.is_empty() {
            debug!(
                "send get blocks proof request to peer: {}, count={}",
                peer,
                blocks_to_prove.len()
            );
            let prove_state_block_hash = if let Some(hash) = peer_state
                .get_prove_state()
                .map(|prove_state| prove_state.get_last_header().header().hash())
            {
                hash
            } else {
                warn!("ignoring, peer {} prove state is none", peer);
                return;
            };
            let content = packed::GetBlocksProof::new_builder()
                .block_hashes(blocks_to_prove.pack())
                .last_hash(prove_state_block_hash)
                .build();
            let message = packed::LightClientMessage::new_builder()
                .set(content.clone())
                .build()
                .as_bytes();
            peers.update_blocks_proof_request(peer, Some(content));
            if let Err(err) =
                nc.send_message(SupportProtocols::LightClient.protocol_id(), peer, message)
            {
                let error_message = format!("nc.send_message LightClientMessage, error: {:?}", err);
                error!("{}", error_message);
            }
        }
    }

    if peer_state.get_blocks_request().is_some() {
        info!("peer {} has an inflight GetBlocks request", peer);
    } else {
        let blocks_to_download =
            peers.get_matched_blocks_to_download(matched_blocks, INIT_BLOCKS_IN_TRANSIT_PER_PEER);
        if !blocks_to_download.is_empty() {
            debug!(
                "send get blocks request to peer: {}, count={}",
                peer,
                blocks_to_download.len()
            );
            peers.update_blocks_request(peer, Some(blocks_to_download.clone()));
            let content = packed::GetBlocks::new_builder()
                .block_hashes(blocks_to_download.pack())
                .build();
            let message = packed::SyncMessage::new_builder()
                .set(content)
                .build()
                .as_bytes();
            if let Err(err) = nc.send_message(SupportProtocols::Sync.protocol_id(), peer, message) {
                let error_message = format!("nc.send_message SyncMessage, error: {:?}", err);
                error!("{}", error_message);
            }
        }
    }
}
