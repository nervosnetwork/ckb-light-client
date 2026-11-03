use crate::protocols::{Peers, GET_BLOCKS_PROOF_LIMIT};
use crate::storage::{canonical, LightClientStorage, Storage};
use ckb_network::{CKBProtocolContext, SupportProtocols};
use ckb_types::{packed, prelude::*, H256};
use log::{debug, info};
use rand::seq::SliceRandom;
use std::collections::HashMap;
use std::sync::Arc;

/// The durable earliest range is authoritative; an old in-memory batch may
/// survive a lost completion acknowledgement or be replaced by a refilter.
pub(crate) fn restore_matched_cache(
    storage: &Storage,
    peers: &Peers,
    matched: &mut HashMap<H256, (bool, Option<packed::Block>)>,
) -> crate::error::Result<bool> {
    let Some(range) = storage.get_earliest_matched_blocks() else {
        let changed = !matched.is_empty();
        peers.clear_matched_blocks(matched);
        return Ok(changed);
    };
    let Some(blocks) = canonical::coverage::cached_matches(storage, &range)? else {
        let changed = !matched.is_empty();
        peers.clear_matched_blocks(matched);
        return Ok(changed);
    };
    let expected: std::collections::HashSet<H256> =
        blocks.iter().map(|(h, _)| h.unpack()).collect();
    if expected.len() == matched.len() && matched.keys().all(|h| expected.contains(h)) {
        for (hash, proved) in blocks {
            if proved {
                matched.get_mut(&hash.unpack()).expect("same durable set").0 = true;
            }
        }
        return Ok(false);
    }
    peers.clear_matched_blocks(matched);
    peers.add_matched_blocks(matched, blocks);
    Ok(true)
}

/// Resume the existing matched-block pipeline after input-creator revalidation.
/// Called under the same matched-block lock as accepted-state transitions.
pub(crate) fn index_downloaded_blocks(
    storage: &Storage,
    peers: &Peers,
    matched: &mut HashMap<H256, (bool, Option<packed::Block>)>,
) -> crate::error::Result<()> {
    canonical::index_ready(storage)?;
    if canonical::coverage::prepare(storage)? {
        peers.clear_matched_blocks(matched);
        return Ok(());
    }
    restore_matched_cache(storage, peers, matched)?;
    if storage.get_earliest_matched_blocks().is_none() {
        // A validated no-match page can commit before its cursor publication.
        // Resume that publication without requiring another block or response.
        storage.update_block_number(storage.get_min_filtered_block_number());
        return Ok(());
    }
    if matched.is_empty() || !peers.all_matched_blocks_downloaded(matched) {
        return Ok(());
    }
    let mut blocks: Vec<_> = matched
        .values()
        .filter_map(|(_, block)| block.clone())
        .collect();
    blocks.sort_by_key(|block| Unpack::<u64>::unpack(&block.header().raw().number()));
    if let Err(error) = canonical::coverage::check_bodies(storage, &blocks) {
        peers.clear_matched_blocks(matched);
        return Err(error);
    }
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
                if let Some((_, _, creator)) = canonical::historical_transaction(storage, &hash)? {
                    let index: u32 = point.index().unpack();
                    if let Some(output) = creator.raw().outputs().get(index as usize) {
                        let watched = scripts
                            .contains(&(output.lock(), crate::storage::ScriptType::Lock))
                            || output.type_().to_opt().is_some_and(|script| {
                                scripts.contains(&(script, crate::storage::ScriptType::Type))
                            });
                        if watched {
                            if let Some(association) = &association {
                                canonical::queue_ordinal_body(storage, &association.header)?;
                                ready = false;
                                continue;
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
            canonical::coverage::restorable_blocks(storage, &next)?,
        );
    }
    if storage.get_earliest_matched_blocks().is_none() {
        storage.update_block_number(storage.get_min_filtered_block_number());
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

    // Each peer gets only work it has not recently reported missing. Empty
    // candidates on one peer must not prevent trying another proved peer.
    let mut candidates = best_peers.clone();
    candidates.shuffle(&mut rand::thread_rng());
    for peer_index in candidates {
        if !peers.can_request_proof(peer_index, &last_hash)
            || peers
                .get_peer(&peer_index)
                .is_none_or(|peer| peer.get_blocks_proof_request().is_some())
        {
            continue;
        }
        let hashes = peers.get_matched_blocks_to_prove(matched_blocks, usize::MAX);
        let hashes = peers
            .matched_blocks_for_peer(peer_index, &last_hash, hashes)
            .into_iter()
            .take(GET_BLOCKS_PROOF_LIMIT)
            .collect::<Vec<_>>();
        if hashes.is_empty() {
            continue;
        }
        let content = packed::GetBlocksProof::new_builder()
            .block_hashes(hashes.pack())
            .last_hash(last_hash.clone())
            .build();
        let message = packed::LightClientMessage::new_builder()
            .set(content.clone())
            .build();
        peers.update_blocks_proof_request(peer_index, Some(content), true);
        if let Err(error) = nc.send_message(
            SupportProtocols::LightClient.protocol_id(),
            peer_index,
            message.as_bytes(),
        ) {
            info!("send matched proof request failed: {error:?}");
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
