use crate::protocols::{Peers, GET_BLOCKS_PROOF_LIMIT};
use crate::storage::{canonical, LightClientStorage, Storage};
use ckb_network::{CKBProtocolContext, SupportProtocols};
use ckb_types::{packed, prelude::*, H256};
use log::{debug, info};
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::Arc;

/// Resume the existing matched-block pipeline after input-creator revalidation.
/// Called under the same matched-block lock as accepted-state transitions.
pub(crate) fn index_downloaded_blocks(
    storage: &Storage,
    peers: &Peers,
    matched: &mut HashMap<H256, (bool, Option<packed::Block>)>,
) -> crate::error::Result<()> {
    canonical::index_ready(storage)?;
    if matched.is_empty() || !peers.all_matched_blocks_downloaded(matched) {
        return Ok(());
    }
    let mut blocks: Vec<_> = matched
        .values()
        .filter_map(|(_, block)| block.clone())
        .collect();
    blocks.sort_by_key(|block| Unpack::<u64>::unpack(&block.header().raw().number()));
    let mut seen = std::collections::HashSet::new();
    let scripts: std::collections::HashSet<_> = storage
        .get_filter_scripts()
        .into_iter()
        .map(|ss| (ss.script, ss.script_type))
        .collect();
    let mut ready = true;
    for block in &blocks {
        if !canonical::anchor_current(storage, &block.header())? {
            return Ok(());
        }
        for tx in block.transactions() {
            for input in tx.raw().inputs() {
                let point = input.previous_output();
                let hash = point.tx_hash();
                if seen.contains(&hash) {
                    continue;
                }
                let association = canonical::transaction(storage, &hash)?;
                if association.as_ref().is_some_and(|tx| tx.index != u32::MAX) {
                    continue;
                }
                // An absent creator was never indexed for our watched history.
                // A retained legacy creator for a watched output must be re-proved.
                if let Some((_, _, creator)) = storage.get_transaction(&hash) {
                    let index: u32 = point.index().unpack();
                    if let Some(output) = creator.raw().outputs().get(index as usize) {
                        let watched = scripts
                            .contains(&(output.lock(), crate::storage::ScriptType::Lock))
                            || output.type_().to_opt().is_some_and(|script| {
                                scripts.contains(&(script, crate::storage::ScriptType::Type))
                            });
                        if watched {
                            if association.is_some() {
                                return Err(crate::error::Error::runtime("watched input ordinal requires its verified block body or reindex"));
                            }
                            ready = false;
                            let fetch = peers.get_tx_fetch_info(&hash);
                            if fetch.is_none() || fetch.is_some_and(|(_, _, missing)| missing) {
                                peers.add_fetch_tx(hash, ckb_systemtime::unix_time_as_millis());
                            }
                        }
                    }
                }
            }
            seen.insert(tx.calc_tx_hash());
        }
    }
    if !ready {
        return Ok(());
    }
    let range = storage
        .get_earliest_matched_blocks()
        .ok_or_else(|| crate::error::Error::runtime("missing watched range"))?;
    let expected: std::collections::HashSet<_> = range
        .blocks
        .iter()
        .map(|block| block.hash.clone())
        .collect();
    if blocks.len() != expected.len()
        || blocks
            .iter()
            .any(|block| !expected.contains(&block.calc_header_hash()))
    {
        return Err(crate::error::Error::runtime(
            "watched range changed before indexing",
        ));
    }
    // Keep the range persisted until all block batches and the cursor commit.
    // A restart can replay an incomplete range; indexing is idempotent.
    canonical::begin_index(storage)?;
    for block in blocks {
        storage.filter_block(block);
    }
    canonical::finish_index(
        storage,
        range.start_number,
        range.start_number + range.blocks_count - 1,
    )?;
    peers.clear_matched_blocks(matched);
    if let Some(next) = storage.get_earliest_matched_blocks() {
        peers.add_matched_blocks(
            matched,
            next.blocks
                .into_iter()
                .map(|block| (block.hash, block.proved))
                .collect(),
        );
    }
    Ok(())
}

pub(crate) fn prove_or_download_matched_blocks(
    peers: Arc<Peers>,
    best_tip: &packed::Header,
    matched_blocks: &HashMap<H256, (bool, Option<packed::Block>)>,
    nc: &dyn CKBProtocolContext,
    init_blocks_in_transit_per_peer: usize,
) {
    info!("in prove_or_download-matched blocks");
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
                    "send get blocks proof request to peer: {}, count={}, {:?}",
                    peer_index,
                    blocks_to_prove.len(),
                    blocks_to_prove,
                );
                let content = packed::GetBlocksProof::new_builder()
                    .block_hashes(blocks_to_prove.pack())
                    .last_hash(last_hash.clone())
                    .build();
                let message = packed::LightClientMessage::new_builder()
                    .set(content.clone())
                    .build()
                    .as_bytes();
                peers.update_blocks_proof_request(*peer_index, Some(content), true);
                if let Err(err) = nc.send_message(
                    SupportProtocols::LightClient.protocol_id(),
                    *peer_index,
                    message,
                ) {
                    let error_message =
                        format!("nc.send_message LightClientMessage, error: {:?}", err);
                    info!("{}", error_message);
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
                    info!("{}", error_message);
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
