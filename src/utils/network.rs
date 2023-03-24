use crate::protocols::{Peers, GET_BLOCKS_PROOF_LIMIT};
use ckb_network::{CKBProtocolContext, SupportProtocols};
use ckb_types::{packed, prelude::*, H256};
use log::{debug, error};
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) fn prove_or_download_matched_blocks(
    peers: Arc<Peers>,
    best_tip: &packed::Header,
    matched_blocks: &HashMap<H256, (bool, Option<packed::Block>)>,
    nc: &dyn CKBProtocolContext,
    init_blocks_in_transit_per_peer: usize,
) {
    let best_peers: Vec<_> = peers.get_best_proved_peers(best_tip);
    let last_hash = best_tip.calc_header_hash();

    loop {
        if let Some(peer_index) = best_peers
            .iter()
            .filter(|peer_index| {
                peers
                    .get_peer(peer_index)
                    .map(|peer| peer.get_blocks_proof_request().is_none())
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>()
            .choose(&mut rand::thread_rng())
            .cloned()
        {
            let blocks_to_prove =
                peers.get_matched_blocks_to_prove(matched_blocks, GET_BLOCKS_PROOF_LIMIT);
            if !blocks_to_prove.is_empty() {
                debug!(
                    "send get blocks proof request to peer: {}, count={}",
                    peer_index,
                    blocks_to_prove.len()
                );
                let content = packed::GetBlocksProof::new_builder()
                    .block_hashes(blocks_to_prove.pack())
                    .last_hash(last_hash.clone())
                    .build();
                let message = packed::LightClientMessage::new_builder()
                    .set(content.clone())
                    .build()
                    .as_bytes();
                peers.update_blocks_proof_request(*peer_index, Some(content));
                if let Err(err) = nc.send_message(
                    SupportProtocols::LightClient.protocol_id(),
                    *peer_index,
                    message,
                ) {
                    let error_message =
                        format!("nc.send_message LightClientMessage, error: {:?}", err);
                    error!("{}", error_message);
                }
            } else {
                break;
            }
        } else {
            debug!("all valid peers are busy for get blocks proof");
            break;
        }
    }

    loop {
        if let Some(peer_index) = best_peers
            .iter()
            .filter(|peer_index| {
                peers
                    .get_peer(peer_index)
                    .map(|peer| peer.get_blocks_request().is_none())
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>()
            .choose(&mut rand::thread_rng())
            .cloned()
        {
            let blocks_to_download = peers
                .get_matched_blocks_to_download(matched_blocks, init_blocks_in_transit_per_peer);
            if !blocks_to_download.is_empty() {
                debug!(
                    "send get blocks request to peer: {}, count={}",
                    peer_index,
                    blocks_to_download.len()
                );
                peers.update_blocks_request(*peer_index, Some(blocks_to_download.clone()));
                let content = packed::GetBlocks::new_builder()
                    .block_hashes(blocks_to_download.pack())
                    .build();
                let message = packed::SyncMessage::new_builder()
                    .set(content)
                    .build()
                    .as_bytes();
                if let Err(err) =
                    nc.send_message(SupportProtocols::Sync.protocol_id(), *peer_index, message)
                {
                    let error_message = format!("nc.send_message SyncMessage, error: {:?}", err);
                    error!("{}", error_message);
                }
            } else {
                break;
            }
        } else {
            debug!("all valid peers are busy for get blocks");
            break;
        }
    }
}
