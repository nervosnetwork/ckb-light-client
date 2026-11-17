//! Durable intent and derived-index repair. Primary transactions/headers and
//! user keys are never used as a source of canonical membership or deleted.
use super::*;
use crate::storage::{KeyPrefix, LightClientStorage, ScriptStatus, SetScriptsCommand};
use serde::{Deserialize, Serialize};

const REGISTRATION: &str = "INDEX_REGISTRATION_V2";
const REPAIR: &str = "INDEX_REPAIR_V2";
const ACCEPT: &str = "CHAIN_ACCEPT_V2";

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "recovery_tests.rs"]
mod tests;

#[derive(Serialize, Deserialize)]
struct Registration {
    scripts: Vec<(Vec<u8>, u8, u64)>,
    command: u8,
}
#[derive(Serialize, Deserialize)]
struct Repair {
    targets: Vec<(Vec<u8>, u64)>,
    initialized: bool,
}
#[derive(Serialize, Deserialize)]
struct Acceptance {
    previous: Vec<u8>,
    work: Vec<u8>,
    tip: Vec<u8>,
    recent: Vec<Vec<u8>>,
    fork: u64,
    filter_cursor: u64,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    bincode::serialize(value).map_err(|e| Error::runtime(format!("recovery journal encode: {e}")))
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes)
        .map_err(|e| Error::runtime(format!("invalid recovery journal: {e}")))
}
fn scan<S: StorageBackend + ?Sized>(
    storage: &S,
    prefix: Vec<u8>,
) -> Result<Vec<super::super::KVPair>> {
    scan_page(storage, prefix, usize::MAX)
}
fn scan_page<S: StorageBackend + ?Sized>(
    storage: &S,
    prefix: Vec<u8>,
    limit: usize,
) -> Result<Vec<super::super::KVPair>> {
    let select = prefix.clone();
    storage.try_collect_iterator(
        IteratorStart::From(prefix),
        IteratorDirection::Forward,
        Box::new(move |key| key.starts_with(&select)),
        Box::new(|_, value| Some(value.to_vec())),
        limit,
    )
}

pub(crate) fn registration_pending<S: StorageBackend + ?Sized>(storage: &S) -> Result<bool> {
    Ok(storage.get(meta(REGISTRATION))?.is_some())
}
pub(crate) fn finish_registration_journal<B: BatchWriter>(batch: &mut B) {
    batch.delete(&meta(REGISTRATION));
}
pub(crate) fn finish_acceptance_journal<B: BatchWriter>(batch: &mut B) {
    batch.delete(&meta(ACCEPT));
}

pub(crate) fn register<S: LightClientStorage + ?Sized>(
    storage: &S,
    scripts: Vec<ScriptStatus>,
    command: SetScriptsCommand,
) -> Result<()> {
    recover(storage)?;
    let prefix = meta(super::super::FILTER_SCRIPTS_KEY);
    let interrupted_index = storage.get(meta(INDEX_WRITING))?.as_deref() == Some(&[1]);
    let mut rewinds = false;
    for script in &scripts {
        let mut key = prefix.clone();
        key.extend(script.script.as_slice());
        key.push(u8::from(matches!(
            script.script_type,
            super::super::ScriptType::Type
        )));
        if let Some(cursor) = storage.get(key)? {
            let cursor = cursor
                .as_slice()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| Error::runtime("invalid registered cursor"))?;
            rewinds |=
                script.block_number < cursor && !matches!(command, SetScriptsCommand::Delete);
        }
    }
    if interrupted_index {
        restart_repair(storage)?;
    } else if rewinds {
        // Existing rows are consistent. Only the requested cursors rewind;
        // per-script indexing replays them behind the saved-coverage fence.
        start_repair(storage, true)?;
    }
    let intent = Registration {
        scripts: scripts
            .into_iter()
            .map(|s| {
                (
                    s.script.as_slice().to_vec(),
                    u8::from(matches!(s.script_type, super::super::ScriptType::Type)),
                    s.block_number,
                )
            })
            .collect(),
        command: match command {
            SetScriptsCommand::All => 0,
            SetScriptsCommand::Partial => 1,
            SetScriptsCommand::Delete => 2,
        },
    };
    let mut batch = storage.batch();
    batch.put(&meta(REGISTRATION), &encode(&intent)?);
    batch.put(&meta(INDEX_WRITING), &[2]);
    batch.commit()?;
    if let Some(bytes) = storage.get(meta(REPAIR))? {
        initialize_repair(storage, decode(&bytes)?)?;
    }
    replay_registration(storage, intent)
}
fn replay_registration<S: LightClientStorage + ?Sized>(
    storage: &S,
    intent: Registration,
) -> Result<()> {
    let mut scripts = intent
        .scripts
        .into_iter()
        .map(|(bytes, kind, number)| {
            Ok(ScriptStatus {
                script: packed::Script::from_slice(&bytes)
                    .map_err(|_| Error::runtime("invalid journal script"))?,
                script_type: match kind {
                    0 => super::super::ScriptType::Lock,
                    1 => super::super::ScriptType::Type,
                    _ => return Err(Error::runtime("invalid journal script kind")),
                },
                block_number: number,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if let Some(bytes) = storage.get(meta(REPAIR))? {
        let repair: Repair = decode(&bytes)?;
        for script in &mut scripts {
            let mut key = meta(super::super::FILTER_SCRIPTS_KEY);
            key.extend(script.script.as_slice());
            key.push(u8::from(matches!(
                script.script_type,
                super::super::ScriptType::Type
            )));
            if repair.targets.iter().any(|(saved, _)| *saved == key) {
                // A registration start height is user intent, not evidence that
                // the missing historical coverage has already been rebuilt.
                let cursor = storage
                    .get(key)?
                    .map(|bytes| {
                        bytes
                            .as_slice()
                            .try_into()
                            .map(u64::from_be_bytes)
                            .map_err(|_| Error::runtime("invalid repair registration cursor"))
                    })
                    .transpose()?
                    .unwrap_or(0);
                script.block_number = script.block_number.min(cursor);
            }
        }
    }
    let command = match intent.command {
        0 => SetScriptsCommand::All,
        1 => SetScriptsCommand::Partial,
        2 => SetScriptsCommand::Delete,
        _ => return Err(Error::runtime("invalid registration command")),
    };
    super::super::storage_trait::apply_filter_scripts(storage, scripts, command);
    complete_repair(storage)
}

/// Save old coverage targets before changing derived rows or active cursors.
fn coverage_targets<S: LightClientStorage + ?Sized>(storage: &S) -> Result<Vec<(Vec<u8>, u64)>> {
    let scripts = scan(storage, meta(super::super::FILTER_SCRIPTS_KEY))?;
    let mut pending_target = storage.get_min_filtered_block_number();
    for row in scan(storage, meta(super::super::MATCHED_FILTER_BLOCKS_KEY))? {
        let prefix_len = meta(super::super::MATCHED_FILTER_BLOCKS_KEY).len();
        let start = row
            .key
            .get(prefix_len..)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| Error::runtime("invalid repair range start"))?;
        let count = row
            .value
            .get(..8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or_else(|| Error::runtime("invalid repair range count"))?;
        let end = start
            .checked_add(count)
            .and_then(|n| n.checked_sub(1))
            .ok_or_else(|| Error::runtime("invalid repair range bounds"))?;
        pending_target = pending_target.max(end);
    }
    scripts
        .into_iter()
        .map(|row| {
            let number = row
                .value
                .as_slice()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| Error::runtime("invalid saved coverage target"))?;
            Ok((row.key, number.max(pending_target)))
        })
        .collect::<Result<Vec<_>>>()
}

fn start_repair<S: LightClientStorage + ?Sized>(storage: &S, initialized: bool) -> Result<()> {
    if storage.get(meta(REPAIR))?.is_some() {
        return Ok(());
    }
    storage.put(
        meta(REPAIR),
        encode(&Repair {
            targets: coverage_targets(storage)?,
            initialized,
        })?,
    )
}
fn restart_repair<S: LightClientStorage + ?Sized>(storage: &S) -> Result<()> {
    let Some(bytes) = storage.get(meta(REPAIR))? else {
        return start_repair(storage, false);
    };
    let mut repair: Repair = decode(&bytes)?;
    for (key, target) in coverage_targets(storage)? {
        if let Some((_, saved)) = repair.targets.iter_mut().find(|(saved, _)| *saved == key) {
            *saved = (*saved).max(target);
        } else {
            repair.targets.push((key, target));
        }
    }
    repair.initialized = false;
    storage.put(meta(REPAIR), encode(&repair)?)
}
fn initialize_repair<S: LightClientStorage + ?Sized>(
    storage: &S,
    mut repair: Repair,
) -> Result<()> {
    if repair.initialized {
        return Ok(());
    }
    let mut batch = storage.batch();
    for (key, _) in &repair.targets {
        batch.put(key, &0u64.to_be_bytes());
    }
    batch.put(
        &meta(super::super::MIN_FILTERED_BLOCK_NUMBER),
        &0u64.to_le_bytes(),
    );
    batch.delete(&meta(INDEX_FORMAT));
    batch.delete(&meta(RECOVERY_FORMAT));
    batch.delete(&meta(INDEX_UNCERTAIN));
    batch.delete(&meta(TRANSITION));
    batch.delete(&meta(INDEX_WRITING));
    // The existing LAST_STATE is an atomically written accepted header, even
    // when an older transition stopped part way through its derived rollback.
    let (_, tip) = storage.get_last_state();
    if storage.get(meta(CONTEXT))?.as_deref() != Some(tip.calc_header_hash().as_slice()) {
        // The old version wrote this cache separately. Binding it now would
        // manufacture fork-prefix evidence. Keep header bytes; discard this cache.
        batch.put(&meta(super::super::LAST_N_HEADERS_KEY), &[]);
    }
    batch.put(&meta(CONTEXT), tip.calc_header_hash().as_slice());
    batch.put(&meta(REPAIR), &encode(&repair)?);
    batch.commit()?;
    // The durable fence survives each bounded deletion batch. Deleted keys are
    // the progress record: restart scans the first remaining keys, so no cursor
    // or non-atomic phase advancement can skip a row.
    // Only derived rows and untrusted provenance are rebuilt. Keep every primary
    // transaction/header/height cache and the complete watched script keys.
    for prefix in [
        vec![KeyPrefix::CellLockScript as u8],
        vec![KeyPrefix::CellTypeScript as u8],
        vec![KeyPrefix::TxLockScript as u8],
        vec![KeyPrefix::TxTypeScript as u8],
        meta(ASSOCIATION),
        meta(MEMBERS),
        meta(super::super::MATCHED_FILTER_BLOCKS_KEY),
    ] {
        loop {
            let rows = scan_page(storage, prefix.clone(), 1024)?;
            if rows.is_empty() {
                break;
            }
            let mut batch = storage.batch();
            for row in rows {
                batch.delete(&row.key);
            }
            batch.commit()?;
        }
    }
    let mut batch = storage.batch();
    let genesis = storage.get_genesis_block();
    member(&mut batch, &genesis.header());
    for (index, tx) in genesis.transactions().into_iter().enumerate() {
        bind(&mut batch, &tx, &genesis.header(), true, index as u32);
    }
    batch.put(&meta(REPAIR), &encode(&repair)?);
    batch.commit()?;
    storage.filter_block(genesis);
    repair.initialized = true;
    storage.put(meta(REPAIR), encode(&repair)?)
}

pub(crate) fn repair_pending<S: StorageBackend + ?Sized>(storage: &S) -> Result<bool> {
    Ok(storage.get(meta(REPAIR))?.is_some())
}
pub(crate) fn complete_repair<S: LightClientStorage + ?Sized>(storage: &S) -> Result<()> {
    let Some(bytes) = storage.get(meta(REPAIR))? else {
        return Ok(());
    };
    let repair: Repair = decode(&bytes)?;
    if !repair.initialized
        || storage.get(meta(INDEX_WRITING))?.is_some()
        || storage.get(meta(TRANSITION))?.is_some()
    {
        return Ok(());
    }
    for (key, target) in repair.targets {
        let Some(cursor) = storage.get(key)? else {
            continue;
        };
        let cursor = cursor
            .as_slice()
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| Error::runtime("invalid repair cursor"))?;
        if cursor < target {
            return Ok(());
        }
    }
    // Persisted pending ranges, including all-missing ranges, still represent
    // incomplete coverage. Existing row reproof alone never completes repair.
    if storage.get_earliest_matched_blocks().is_some() {
        return Ok(());
    }
    let mut batch = storage.batch();
    initialize_index_format(&mut batch);
    batch.delete(&meta(REPAIR));
    // Queries that started before repair must detect a complete clear/rebuild,
    // even when the accepted tip and the final row set are unchanged.
    finish_revision(storage, &mut batch)?;
    batch.commit()
}

pub(crate) fn accept_with_rollback<S: LightClientStorage + ?Sized>(
    storage: &S,
    work: &U256,
    tip: &packed::Header,
    recent: &[HeaderView],
    fork: u64,
) -> Result<()> {
    let already_repairing = repair_pending(storage)?;
    if fork == 0 || storage.get(meta(INDEX_WRITING))?.is_some() {
        // A partially indexed range needs a rescan through its OLD saved target,
        // not just through the cursor left after rollback.
        restart_repair(storage)?;
    }
    let prefix = meta(super::super::MATCHED_FILTER_BLOCKS_KEY);
    let mut filter_cursor = storage.get_min_filtered_block_number().min(fork);
    let mut overlaps = false;
    for row in scan(storage, prefix.clone())? {
        let start = row
            .key
            .get(prefix.len()..)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| Error::runtime("invalid journal range start"))?;
        let count = row
            .value
            .get(..8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or_else(|| Error::runtime("invalid journal range count"))?;
        if start
            .checked_add(count)
            .is_none_or(|end| end > fork.saturating_add(1))
        {
            overlaps = true;
            filter_cursor = filter_cursor.min(start.saturating_sub(1));
        }
    }
    if overlaps {
        start_repair(storage, true)?;
    }
    let mut candidate_repair = None;
    if !already_repairing {
        if let Some(bytes) = storage.get(meta(REPAIR))? {
            let mut repair: Repair = decode(&bytes)?;
            // Heights above a shorter replacement tip no longer describe
            // current-chain coverage. Existing independent repair goals remain.
            let tip_number: u64 = tip.raw().number().unpack();
            for (_, target) in &mut repair.targets {
                *target = (*target).min(tip_number);
            }
            // Keep old-chain goals durable until candidate intent is durable.
            // Replay sees this transformation only together with ACCEPT and
            // TRANSITION, so it cannot certify a shorter prefix of the old chain.
            candidate_repair = Some(encode(&repair)?);
        }
    }
    let intent = Acceptance {
        previous: storage
            .get_last_state()
            .1
            .calc_header_hash()
            .as_slice()
            .to_vec(),
        work: work.to_le_bytes().to_vec(),
        tip: tip.as_slice().to_vec(),
        recent: recent
            .iter()
            .map(|h| h.data().as_slice().to_vec())
            .collect(),
        fork,
        filter_cursor,
    };
    let mut batch = storage.batch();
    if let Some(repair) = candidate_repair {
        batch.put(&meta(REPAIR), &repair);
    }
    batch.put(&meta(ACCEPT), &encode(&intent)?);
    batch.put(&meta(TRANSITION), &[1]);
    batch.commit()?;
    replay_acceptance(storage, intent)?;
    recover(storage)
}
fn replay_acceptance<S: LightClientStorage + ?Sized>(
    storage: &S,
    intent: Acceptance,
) -> Result<()> {
    let tip = packed::Header::from_slice(&intent.tip)
        .map_err(|_| Error::runtime("invalid journal accepted tip"))?;
    let work = U256::from_le_bytes(
        intent
            .work
            .as_slice()
            .try_into()
            .map_err(|_| Error::runtime("invalid journal work"))?,
    );
    let recent = intent
        .recent
        .into_iter()
        .map(|h| {
            packed::Header::from_slice(&h)
                .map(|h| h.into_view())
                .map_err(|_| Error::runtime("invalid journal recent header"))
        })
        .collect::<Result<Vec<_>>>()?;
    if storage.get_last_state().1.calc_header_hash().as_slice() != intent.previous.as_slice() {
        return Err(Error::runtime(
            "accepted rollback journal belongs to a different state",
        ));
    }
    // Every stage is idempotent. Keep intent until the new accepted context and
    // journal removal commit atomically in update_state.
    storage.rollback_to_block(
        intent
            .fork
            .checked_add(1)
            .ok_or_else(|| Error::runtime("invalid fork boundary"))?,
    );
    let prefix = meta(super::super::MATCHED_FILTER_BLOCKS_KEY);
    let mut batch = storage.batch();
    for row in scan(storage, prefix.clone())? {
        let start = row
            .key
            .get(prefix.len()..)
            .and_then(|n| n.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| Error::runtime("invalid pending range key"))?;
        let count = row
            .value
            .get(..8)
            .and_then(|n| n.try_into().ok())
            .map(u64::from_le_bytes)
            .ok_or_else(|| Error::runtime("invalid pending range"))?;
        if start
            .checked_add(count)
            .is_none_or(|end| end > intent.fork.saturating_add(1))
        {
            batch.delete(&row.key);
        }
    }
    batch.put(
        &meta(super::super::MIN_FILTERED_BLOCK_NUMBER),
        &intent.filter_cursor.to_le_bytes(),
    );
    batch.commit()?;
    update_state(storage, &work, &tip, &recent, Some(intent.fork))
}

pub(crate) fn recover<S: LightClientStorage + ?Sized>(storage: &S) -> Result<()> {
    if let Some(bytes) = storage.get(meta(ACCEPT))? {
        replay_acceptance(storage, decode(&bytes)?)?;
    }
    // A bare legacy marker has no recoverable intent. Repair derived coverage in
    // place; never clear it and claim the old rows are complete.
    let registration = storage.get(meta(REGISTRATION))?;
    let damaged = storage.get(meta(TRANSITION))?.is_some()
        || storage.get(meta(INDEX_UNCERTAIN))?.is_some()
        || (storage.get(meta(INDEX_WRITING))?.as_deref() == Some(&[2]) && registration.is_none());
    if damaged {
        restart_repair(storage)?;
    } else if storage.get(meta(INDEX_FORMAT))?.as_deref() != Some(&[1])
        || storage.get(meta(RECOVERY_FORMAT))?.as_deref() != Some(&[2])
    {
        start_repair(storage, false)?;
    }
    if let Some(bytes) = storage.get(meta(REPAIR))? {
        initialize_repair(storage, decode(&bytes)?)?;
    }
    if let Some(bytes) = registration {
        replay_registration(storage, decode(&bytes)?)?;
    }
    // Reconstruct positional evidence through bounded filter pages, not cached
    // headers or legacy booleans. Preserve saved goals before any rewind.
    super::coverage::prepare(storage)?;
    if storage.get_earliest_matched_blocks().is_none()
        && storage.get(meta(INDEX_WRITING))?.is_none()
        && storage.get(meta(TRANSITION))?.is_none()
    {
        storage.update_block_number(storage.get_min_filtered_block_number());
    }
    complete_repair(storage)
}

/// Coverage rechecks reuse the saved-target repair fence; no primary rows are cleared.
pub(super) fn save_recheck_targets<S: LightClientStorage + ?Sized>(storage: &S) -> Result<()> {
    start_repair(storage, true)
}
pub(super) fn repair_ambiguous_index<S: LightClientStorage + ?Sized>(storage: &S) -> Result<()> {
    restart_repair(storage)?;
    let repair = decode(
        &storage
            .get(meta(REPAIR))?
            .ok_or_else(|| Error::runtime("missing repair intent"))?,
    )?;
    initialize_repair(storage, repair)
}
