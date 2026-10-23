//! Sparse accepted-chain membership, separate from historical bytes/height caches.
//! Writers are trusted local code; this is not an authenticated database format.
//! Proof anchor checks and commits require the existing single accepting protocol
//! handler. They are synchronous and do not form a database compare-and-swap.
//! Acceptance and watched indexing also share the matched-block write lock.
use super::{
    BatchWriter, HeaderWithExtension, IteratorDirection, IteratorStart, Key, StorageBackend, Value,
    LAST_STATE_KEY,
};
use crate::error::{Error, Result};
use ckb_types::{core::HeaderView, packed, prelude::*, U256};

const ASSOCIATION: &str = "TX_BLOCK_V1:";
const MEMBERS: &str = "CHAIN_BLOCK_V1:";
const CONTEXT: &str = "CHAIN_CONTEXT_V1";
const TRANSITION: &str = "CHAIN_TRANSITION_V1";
const INDEX_UNCERTAIN: &str = "INDEX_UNCERTAIN_V1";
const INDEX_FORMAT: &str = "INDEX_ASSOCIATIONS_V1";
const INDEX_WRITING: &str = "INDEX_WRITING_V1";
const INDEX_REVISION: &str = "INDEX_REVISION_V1";

fn meta(name: &str) -> Vec<u8> {
    Key::Meta(name).into_vec()
}
pub(crate) fn association_key(hash: &packed::Byte32) -> Vec<u8> {
    let mut key = meta(ASSOCIATION);
    key.extend_from_slice(hash.as_slice());
    key
}
pub(crate) fn member_key(number: u64) -> Vec<u8> {
    let mut key = meta(MEMBERS);
    key.extend_from_slice(&number.to_be_bytes());
    key
}
pub(crate) fn bind<B: BatchWriter>(
    batch: &mut B,
    tx: &packed::Transaction,
    header: &packed::Header,
    verified: bool,
    index: u32,
) {
    let mut value = vec![u8::from(verified)];
    value.extend_from_slice(&Unpack::<u64>::unpack(&header.raw().number()).to_be_bytes());
    value.extend_from_slice(&index.to_be_bytes());
    value.extend_from_slice(header.calc_header_hash().as_slice());
    batch.put(&association_key(&tx.calc_tx_hash()), &value);
}
pub(crate) fn member<B: BatchWriter>(batch: &mut B, header: &packed::Header) {
    batch.put(
        &member_key(header.raw().number().unpack()),
        header.calc_header_hash().as_slice(),
    );
}
fn parse_tip(bytes: Option<&[u8]>) -> Option<HeaderView> {
    packed::Header::from_slice(bytes?.get(32..)?)
        .ok()
        .map(|h| h.into_view())
}
pub(crate) fn extends(
    previous: &packed::Header,
    tip: &packed::Header,
    recent: &[HeaderView],
) -> bool {
    let previous = previous.clone().into_view();
    let tip = tip.clone().into_view();
    if previous.hash() == tip.hash() {
        return true;
    }
    let mut next = tip;
    for header in recent.iter().rev() {
        if next.parent_hash() == previous.hash()
            && previous.number().checked_add(1) == Some(next.number())
        {
            return true;
        }
        if header.hash() != next.parent_hash()
            || header.number().checked_add(1) != Some(next.number())
        {
            return false;
        }
        next = header.clone();
    }
    next.parent_hash() == previous.hash() && previous.number().checked_add(1) == Some(next.number())
}
pub(crate) fn begin_transition<S: StorageBackend + ?Sized>(storage: &S) -> Result<()> {
    let mut batch = storage.batch();
    // A previous rollback may have stopped between index batches. A later fork
    // proves chain membership, but cannot certify those partially restored rows.
    if storage.get(meta(TRANSITION))?.is_some() {
        batch.put(&meta(INDEX_UNCERTAIN), &[1]);
    }
    batch.put(&meta(TRANSITION), &[1]);
    batch.commit()
}
pub(crate) fn invalidate<S: StorageBackend + ?Sized>(
    storage: &S,
    batch: &mut S::Batch,
    from: u64,
) -> Result<()> {
    let prefix = meta(MEMBERS);
    let rows = storage.try_collect_iterator(
        IteratorStart::From(member_key(from.max(1))),
        IteratorDirection::Forward,
        Box::new(move |key| key.starts_with(&prefix)),
        Box::new(|_, value| Some(value.to_vec())),
        usize::MAX,
    )?;
    for row in rows {
        batch.delete(&row.key);
    }
    Ok(())
}
pub(crate) fn update_state<S: StorageBackend + ?Sized>(
    storage: &S,
    work: &U256,
    tip: &packed::Header,
    recent: &[HeaderView],
    fork: Option<u64>,
) -> Result<()> {
    let old = storage.get(meta(LAST_STATE_KEY))?;
    let previous = parse_tip(old.as_deref());
    if old.is_some() && previous.is_none() {
        return Err(Error::runtime("invalid previous accepted state"));
    }
    // A legacy/crash-mismatched recent window cannot authenticate a fork prefix.
    // Only windows atomically bound to the previous accepted header may retain it.
    let context = storage.get(meta(CONTEXT))?;
    let fork = fork.filter(|_| {
        previous
            .as_ref()
            .is_some_and(|header| context.as_deref() == Some(header.hash().as_slice()))
    });
    let interrupted = storage.get(meta(TRANSITION))?.is_some();
    let uncertain = (interrupted
        || previous
            .as_ref()
            .is_some_and(|old| old.number() > 0 && !extends(&old.data(), tip, recent)))
        && fork.is_none();
    let mut batch = storage.batch();
    if let Some(fork) = fork {
        invalidate(storage, &mut batch, fork.saturating_add(1))?;
        if storage.get(meta(INDEX_WRITING))?.is_some() {
            // The old cursor cannot describe partially indexed writes after a crash.
            batch.put(&meta(INDEX_UNCERTAIN), &[1]);
        }
    } else if uncertain {
        invalidate(storage, &mut batch, 1)?;
        batch.put(&meta(INDEX_UNCERTAIN), &[1]);
    }
    super::storage_trait::write_last_state(&mut batch, work, tip, recent);
    batch.put(&meta(CONTEXT), tip.calc_header_hash().as_slice());
    batch.delete(&meta(TRANSITION));
    batch.commit()
}

/// An old response is usable only if its actual anchor is still known on our chain.
/// A hash in the atomically bound verified recent window is sufficient; height alone is not.
pub(crate) fn anchor_current<S: StorageBackend + ?Sized>(
    storage: &S,
    anchor: &packed::Header,
) -> Result<bool> {
    let rows = storage.get_many(&[
        meta(LAST_STATE_KEY),
        meta("LAST_N_HEADERS"),
        meta(CONTEXT),
        meta(TRANSITION),
        member_key(anchor.raw().number().unpack()),
    ])?;
    if rows.len() != 5 {
        return Err(Error::runtime("incomplete chain snapshot"));
    }
    if rows[3].is_some() {
        return Ok(false);
    }
    let tip =
        parse_tip(rows[0].as_deref()).ok_or_else(|| Error::runtime("invalid accepted state"))?;
    if rows[2]
        .as_deref()
        .is_some_and(|context| context != tip.hash().as_slice())
    {
        return Err(Error::runtime("accepted state and chain context disagree"));
    }
    let hash = anchor.calc_header_hash();
    if hash == tip.hash() {
        return Ok(true);
    }
    if rows[4].as_deref() == Some(hash.as_slice()) {
        return Ok(true);
    }
    if rows[2].as_deref() != Some(tip.hash().as_slice()) {
        return Ok(false);
    }
    let Some(window) = rows[1].as_deref() else {
        return Ok(false);
    };
    if window.len() % 40 != 0 {
        return Err(Error::runtime("invalid recent window"));
    }
    let number: u64 = anchor.raw().number().unpack();
    Ok(window
        .chunks_exact(40)
        .any(|row| row[..8] == number.to_le_bytes() && &row[8..] == hash.as_slice()))
}

pub(crate) fn store_proved_header<S: StorageBackend + ?Sized>(
    storage: &S,
    hwe: &HeaderWithExtension,
    anchor: &packed::Header,
) -> Result<()> {
    if !anchor_current(storage, anchor)? {
        return Err(Error::runtime("obsolete proof anchor"));
    }
    let mut batch = storage.batch();
    batch.put(
        &Key::BlockHash(&hwe.header.calc_header_hash()).into_vec(),
        &Vec::<u8>::from(Value::HeaderWithExtension(hwe)),
    );
    // Preserve the legacy availability cache; canonical readers never trust it.
    batch.put(
        &Key::BlockNumber(hwe.header.raw().number().unpack()).into_vec(),
        hwe.header.calc_header_hash().as_slice(),
    );
    member(&mut batch, &hwe.header);
    batch.commit()
}
pub(crate) fn store_proved_transaction<S: StorageBackend + ?Sized>(
    storage: &S,
    tx: &packed::Transaction,
    index: u32,
    hwe: &HeaderWithExtension,
    anchor: &packed::Header,
) -> Result<()> {
    if !anchor_current(storage, anchor)? {
        return Err(Error::runtime("obsolete proof anchor"));
    }
    // A proof can refresh membership without discarding a body-established ordinal.
    let index = if index == u32::MAX {
        transaction(storage, &tx.calc_tx_hash())?
            .filter(|old| old.header.calc_header_hash() == hwe.header.calc_header_hash())
            .map_or(index, |old| old.index)
    } else {
        index
    };
    let mut batch = storage.batch();
    batch.put(
        &Key::TxHash(&tx.calc_tx_hash()).into_vec(),
        &Vec::<u8>::from(Value::Transaction(
            hwe.header.raw().number().unpack(),
            index,
            tx,
        )),
    );
    batch.put(
        &Key::BlockHash(&hwe.header.calc_header_hash()).into_vec(),
        &Vec::<u8>::from(Value::HeaderWithExtension(hwe)),
    );
    batch.put(
        &Key::BlockNumber(hwe.header.raw().number().unpack()).into_vec(),
        hwe.header.calc_header_hash().as_slice(),
    );
    bind(&mut batch, tx, &hwe.header, true, index);
    member(&mut batch, &hwe.header);
    batch.commit()
}

// Witness bytes are not independently authenticated by a transaction inclusion proof.
// Classify cellbase from its included raw input, not the optional witness vector.
pub(crate) fn resolver_index(tx: &packed::Transaction, index: u32) -> u32 {
    if index == u32::MAX
        && tx.raw().inputs().len() == 1
        && tx
            .raw()
            .inputs()
            .get(0)
            .expect("one input")
            .previous_output()
            .is_null()
    {
        0
    } else {
        index
    }
}

pub(crate) struct CanonicalTransaction {
    pub transaction: packed::Transaction,
    pub header: packed::Header,
    pub number: u64,
    pub index: u32,
}
pub(crate) fn transaction<S: StorageBackend + ?Sized>(
    storage: &S,
    hash: &packed::Byte32,
) -> Result<Option<CanonicalTransaction>> {
    // Retry local key-selection races before treating membership as unavailable.
    for _ in 0..3 {
        let key = association_key(hash);
        let preview = storage.get(key.clone())?;
        let Some(binding) = preview.as_deref().filter(|v| v.len() == 45 && v[0] == 1) else {
            return Ok(None);
        };
        let number = u64::from_be_bytes(binding[1..9].try_into().expect("checked length"));
        let block_hash = packed::Byte32::from_slice(&binding[13..])
            .map_err(|_| Error::runtime("invalid inclusion hash"))?;
        let rows = storage.get_many(&[
            Key::TxHash(hash).into_vec(),
            key,
            member_key(number),
            Key::BlockHash(&block_hash).into_vec(),
            meta(TRANSITION),
            meta(LAST_STATE_KEY),
            meta(CONTEXT),
        ])?;
        if rows.len() != 7 {
            return Err(Error::runtime("incomplete transaction snapshot"));
        }
        if rows[1] != preview {
            continue;
        }
        if rows[4].is_some() || rows[2].as_deref() != Some(block_hash.as_slice()) {
            return Ok(None);
        }
        let accepted = parse_tip(rows[5].as_deref())
            .ok_or_else(|| Error::runtime("invalid accepted state in transaction snapshot"))?;
        if rows[6]
            .as_deref()
            .is_some_and(|context| context != accepted.hash().as_slice())
        {
            return Err(Error::runtime("accepted state and chain context disagree"));
        }
        if number > accepted.number()
            || (number == accepted.number() && block_hash != accepted.hash())
        {
            return Err(Error::runtime("inclusion is above accepted state"));
        }
        let Some(bytes) = rows[0].as_deref() else {
            return Ok(None);
        };
        let stored_number = bytes
            .get(..8)
            .and_then(|v| v.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| Error::runtime("invalid transaction height"))?;
        let index = bytes
            .get(8..12)
            .and_then(|v| v.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or_else(|| Error::runtime("invalid transaction index"))?;
        let tx = bytes
            .get(12..)
            .and_then(|v| packed::Transaction::from_slice(v).ok())
            .ok_or_else(|| Error::runtime("invalid transaction bytes"))?;
        let header = rows[3]
            .as_deref()
            .and_then(|v| v.get(..packed::Header::TOTAL_SIZE))
            .and_then(|v| packed::Header::from_slice(v).ok())
            .ok_or_else(|| Error::runtime("invalid inclusion header"))?;
        if tx.calc_tx_hash() != *hash
            || stored_number != number
            || binding[9..13] != index.to_be_bytes()
            || Unpack::<u64>::unpack(&header.raw().number()) != number
            || header.calc_header_hash() != block_hash
        {
            return Err(Error::runtime("inconsistent transaction association"));
        }
        return Ok(Some(CanonicalTransaction {
            transaction: tx,
            header,
            number,
            index,
        }));
    }
    Err(Error::runtime(
        "canonical_state:retry: transaction observation changed",
    ))
}
pub(crate) fn indexed_transaction<S: StorageBackend + ?Sized>(
    storage: &S,
    hash: &packed::Byte32,
    number: u64,
    index: u32,
) -> Result<packed::Transaction> {
    let tx = transaction(storage, hash)?.ok_or_else(|| {
        Error::runtime("canonical_state:rebuild_required: indexed transaction needs proof revalidation or a separately rebuilt database")
    })?;
    if tx.number != number || tx.index != index {
        return Err(Error::runtime(
            "canonical_state:rebuild_required: indexed position differs from verified inclusion",
        ));
    }
    Ok(tx.transaction)
}
pub(crate) fn index_ready<S: StorageBackend + ?Sized>(storage: &S) -> Result<()> {
    let rows = storage.get_many(&[meta(TRANSITION), meta(INDEX_UNCERTAIN), meta(INDEX_WRITING)])?;
    if rows.len() != 3 || rows[0].is_some() || rows[1].is_some() || rows[2].as_deref() == Some(&[2])
    {
        return Err(Error::runtime(
            "canonical_state:rebuild_required: watched index interrupted or chain continuity unknown; rebuild in a separate database and retain this database",
        ));
    }
    Ok(())
}
pub(crate) fn query_context<S: StorageBackend + ?Sized>(storage: &S) -> Result<Vec<u8>> {
    index_ready(storage)?;
    let rows = storage.get_many(&[
        meta(LAST_STATE_KEY),
        meta(TRANSITION),
        meta(INDEX_UNCERTAIN),
        meta(INDEX_FORMAT),
        meta(INDEX_WRITING),
        meta(INDEX_REVISION),
        meta(CONTEXT),
    ])?;
    if rows.len() != 7
        || rows[1].is_some()
        || rows[2].is_some()
        || rows[3].as_deref() != Some(&[1])
        || rows[4].is_some()
    {
        return Err(Error::runtime(
            "canonical_state:rebuild_required: watched index coverage is unverified; rebuild in a separate database and retain this database",
        ));
    }
    let mut state = rows[0]
        .clone()
        .ok_or_else(|| Error::runtime("missing accepted state"))?;
    let tip = parse_tip(Some(&state)).ok_or_else(|| Error::runtime("invalid accepted state"))?;
    if rows[6]
        .as_deref()
        .is_some_and(|context| context != tip.hash().as_slice())
    {
        return Err(Error::runtime("accepted state and chain context disagree"));
    }
    if let Some(revision) = &rows[5] {
        state.extend_from_slice(revision);
    }
    Ok(state)
}
pub(crate) fn check_query_context<S: StorageBackend + ?Sized>(
    storage: &S,
    context: &[u8],
) -> Result<()> {
    if query_context(storage)? != context {
        return Err(Error::runtime(
            "canonical_state:retry: chain or watched index changed during query",
        ));
    }
    Ok(())
}
pub(crate) fn begin_index<S: StorageBackend + ?Sized>(storage: &S) -> Result<()> {
    storage.put(meta(INDEX_WRITING), vec![1])
}

/// Fence registration and report whether genesis indexing is safe.
pub(crate) fn begin_registration<S: StorageBackend + ?Sized>(storage: &S) -> Result<bool> {
    let interrupted = storage.get(meta(TRANSITION))?.is_some();
    let mut batch = storage.batch();
    if interrupted || storage.get(meta(INDEX_WRITING))?.is_some() {
        batch.put(&meta(INDEX_UNCERTAIN), &[1]);
    }
    batch.put(&meta(INDEX_WRITING), &[2]);
    batch.commit()?;
    Ok(!interrupted)
}
fn finish_revision<S: StorageBackend + ?Sized>(storage: &S, batch: &mut S::Batch) -> Result<()> {
    let previous = storage.get(meta(INDEX_REVISION))?;
    let revision = match previous {
        Some(bytes) => u64::from_be_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::runtime("invalid index revision"))?,
        ),
        None => 0,
    }
    .checked_add(1)
    .ok_or_else(|| Error::runtime("index revision overflow"))?;
    batch.put(&meta(INDEX_REVISION), &revision.to_be_bytes());
    batch.delete(&meta(INDEX_WRITING));
    Ok(())
}
pub(crate) fn finish_registration<S: StorageBackend + ?Sized>(storage: &S) -> Result<()> {
    let mut batch = storage.batch();
    finish_revision(storage, &mut batch)?;
    batch.commit()
}

/// Finish a replayable range in one batch: cursor, range removal and read fence.
pub(crate) fn finish_index<S: super::LightClientStorage + ?Sized>(
    storage: &S,
    start: u64,
    end: u64,
) -> Result<()> {
    let prefix = meta("FILTER_SCRIPTS");
    let select = prefix.clone();
    let rows = storage.try_collect_iterator(
        IteratorStart::From(prefix),
        IteratorDirection::Forward,
        Box::new(move |key| key.starts_with(&select)),
        Box::new(|_, value| Some(value.to_vec())),
        usize::MAX,
    )?;
    let mut batch = storage.batch();
    for row in rows {
        let number = row
            .value
            .as_slice()
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| Error::runtime("invalid script cursor"))?;
        if number < end {
            batch.put(&row.key, &end.to_be_bytes());
        }
    }
    let mut range = meta("MATCHED_BLOCKS");
    range.extend_from_slice(&start.to_be_bytes());
    batch.delete(&range);
    finish_revision(storage, &mut batch)?;
    batch.commit()
}
