//! Pending filter coverage is the single durable source of positional expectations.
//! The first eight bytes retain the legacy count for rollback/coverage-target readers.
use super::*;
use crate::storage::LightClientStorage;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const MAGIC: &[u8] = b"\0CKBPOS1";
const SCRIPTS_REVISION: &str = "FILTER_SCRIPT_REVISION_V1";

#[derive(Serialize, Deserialize)]
pub(crate) struct Positions {
    anchor: Vec<u8>,
    scripts_revision: u64,
    recheck: bool,
    // height, hash, indexed. The last flag is written with the body index batch.
    matches: Vec<(u64, [u8; 32], bool)>,
}
pub(crate) struct Range {
    pub count: u64,
    pub blocks: Vec<(packed::Byte32, bool)>,
    positions: Option<Positions>,
}
pub(crate) fn key(start: u64) -> Vec<u8> {
    let mut key = meta(super::super::MATCHED_FILTER_BLOCKS_KEY);
    key.extend(start.to_be_bytes());
    key
}
fn bounds(start: u64, count: u64) -> Result<u64> {
    if count == 0 || start == 0 {
        return Err(Error::runtime("invalid pending coverage bounds"));
    }
    start
        .checked_add(count - 1)
        .ok_or_else(|| Error::runtime("coverage overflow"))
}
pub(crate) fn decode(bytes: &[u8]) -> Result<Range> {
    let count = bytes
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| Error::runtime("invalid pending coverage count"))?;
    let body = &bytes[8..];
    if !body.len().is_multiple_of(33) {
        let framed = body
            .strip_prefix(MAGIC)
            .ok_or_else(|| Error::runtime("unknown coverage format"))?;
        let length = framed
            .get(..8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
            .and_then(|n| usize::try_from(n).ok())
            .ok_or_else(|| Error::runtime("invalid coverage frame length"))?;
        let payload_end = 8usize
            .checked_add(length)
            .ok_or_else(|| Error::runtime("coverage frame overflow"))?;
        let payload = framed
            .get(8..payload_end)
            .ok_or_else(|| Error::runtime("truncated coverage frame"))?;
        let padding = &framed[payload_end..];
        if !padding.is_empty() && padding != [0] {
            return Err(Error::runtime("invalid coverage padding"));
        }
        let positions: Positions = bincode::deserialize(payload)
            .map_err(|e| Error::runtime(format!("invalid coverage positions: {e}")))?;
        let blocks = positions
            .matches
            .iter()
            .map(|(_, hash, _)| (hash.pack(), false))
            .collect();
        Ok(Range {
            count,
            blocks,
            positions: Some(positions),
        })
    } else {
        let blocks = body
            .chunks_exact(33)
            .map(|b| {
                packed::Byte32::from_slice(&b[..32])
                    .map(|hash| (hash, b[32] == 1))
                    .map_err(|_| Error::runtime("invalid legacy match"))
            })
            .collect::<Result<_>>()?;
        Ok(Range {
            count,
            blocks,
            positions: None,
        })
    }
}
fn encode(range: &Range) -> Result<Vec<u8>> {
    let mut bytes = range.count.to_le_bytes().to_vec();
    if let Some(positions) = &range.positions {
        bytes.extend(MAGIC);
        let payload = bincode::serialize(positions).map_err(|e| Error::runtime(e.to_string()))?;
        bytes.extend((payload.len() as u64).to_le_bytes());
        bytes.extend(payload);
        // Legacy rows are exactly count + N * (hash, bool). Keep the formats
        // disjoint even if a legacy hash happens to begin with MAGIC.
        if (bytes.len() - 8).is_multiple_of(33) {
            bytes.push(0);
        }
    } else {
        for (hash, proved) in &range.blocks {
            bytes.extend(hash.as_slice());
            bytes.push(u8::from(*proved));
        }
    }
    Ok(bytes)
}
pub(crate) fn scripts_revision<S: StorageBackend + ?Sized>(storage: &S) -> Result<u64> {
    storage
        .get(meta(SCRIPTS_REVISION))?
        .map(|b| {
            b.as_slice()
                .try_into()
                .map(u64::from_be_bytes)
                .map_err(|_| Error::runtime("invalid filter script revision"))
        })
        .transpose()
        .map(|v| v.unwrap_or(0))
}
pub(super) fn change_scripts<S: StorageBackend + ?Sized>(
    storage: &S,
    batch: &mut S::Batch,
) -> Result<()> {
    let next = scripts_revision(storage)?
        .checked_add(1)
        .ok_or_else(|| Error::runtime("filter script revision overflow"))?;
    batch.put(&meta(SCRIPTS_REVISION), &next.to_be_bytes());
    Ok(())
}
fn load<S: StorageBackend + ?Sized>(storage: &S, start: u64) -> Result<Range> {
    decode(
        &storage
            .get(key(start))?
            .ok_or_else(|| Error::runtime("pending coverage disappeared"))?,
    )
}
fn current<S: StorageBackend + ?Sized>(storage: &S, start: u64, range: &Range) -> Result<bool> {
    let end = bounds(start, range.count)?;
    let Some(p) = &range.positions else {
        return Ok(false);
    };
    if p.recheck || p.scripts_revision != scripts_revision(storage)? {
        return Ok(false);
    }
    let anchor = packed::Header::from_slice(&p.anchor)
        .map_err(|_| Error::runtime("invalid coverage anchor"))?;
    if end > Unpack::<u64>::unpack(&anchor.raw().number()) || !anchor_current(storage, &anchor)? {
        return Ok(false);
    }
    let mut hashes = HashSet::new();
    let mut previous = None;
    for (number, hash, _) in &p.matches {
        if *number < start
            || *number > end
            || previous.is_some_and(|n| n >= *number)
            || !hashes.insert(hash)
        {
            return Err(Error::runtime("invalid/duplicate coverage positions"));
        }
        previous = Some(*number);
    }
    Ok(true)
}

/// Save goals before rewinding. The old obligation remains durable until a
/// validated filter page atomically replaces it (and retains any unprocessed tail).
pub(crate) fn recheck<S: LightClientStorage + ?Sized>(storage: &S, start: u64) -> Result<()> {
    let mut range = load(storage, start)?;
    bounds(start, range.count)?;
    if storage.get(meta(INDEX_WRITING))?.as_deref() == Some(&[1]) {
        // Legacy/changed partially indexed rows cannot be repaired by a reproof.
        return recovery::repair_ambiguous_index(storage);
    }
    recovery::save_recheck_targets(storage)?;
    if let Some(p) = &mut range.positions {
        p.recheck = true;
    }
    let mut batch = storage.batch();
    batch.put(&key(start), &encode(&range)?);
    batch.put(
        &meta(super::super::MIN_FILTERED_BLOCK_NUMBER),
        &storage
            .get_min_filtered_block_number()
            .min(start - 1)
            .to_le_bytes(),
    );
    // The saved target is a coverage obligation, not permission to exclude a
    // script from the refilter. Rewind cursors atomically; the repair fence
    // prevents replayed creators exposing spent outputs before the saved goal.
    let prefix = meta(super::super::FILTER_SCRIPTS_KEY);
    let select = prefix.clone();
    for row in storage.try_collect_iterator(
        IteratorStart::From(prefix),
        IteratorDirection::Forward,
        Box::new(move |k| k.starts_with(&select)),
        Box::new(|_, v| Some(v.to_vec())),
        usize::MAX,
    )? {
        let cursor = row
            .value
            .as_slice()
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| Error::runtime("invalid recheck script cursor"))?;
        if cursor >= start {
            batch.put(&row.key, &(start - 1).to_be_bytes());
        }
    }

    bump_revision(storage, &mut batch)?;
    batch.commit()
}
pub(crate) fn prepare<S: LightClientStorage + ?Sized>(storage: &S) -> Result<bool> {
    let Some(first) = storage.get_earliest_matched_blocks() else {
        return Ok(false);
    };
    let range = load(storage, first.start_number)?;
    if !current(storage, first.start_number, &range)? {
        recheck(storage, first.start_number)?;
        return Ok(true);
    }
    Ok(false)
}

/// Called only after validating the filter hash chain and matching its script
/// data. Script updates, acceptance, proof admission and indexing share the
/// matched-block lock; the revision is captured before computing the matches.
pub(crate) fn save_filters<S: LightClientStorage + ?Sized>(
    storage: &S,
    start: u64,
    count: u64,
    matches: Vec<(u64, packed::Byte32)>,
    revision: u64,
) -> Result<()> {
    index_ready(storage)?;
    let end = bounds(start, count)?;
    let page_count = usize::try_from(count).map_err(|_| Error::runtime("filter page too large"))?;
    if recheck_limit(storage, start, page_count)? != page_count {
        return Err(Error::runtime(
            "filter page crosses an existing pending range boundary",
        ));
    }
    if revision != scripts_revision(storage)? {
        return Err(Error::runtime("filter script revision changed"));
    }
    let anchor = storage.get_tip_header();
    if end > Unpack::<u64>::unpack(&anchor.raw().number()) {
        return Err(Error::runtime(
            "filter coverage extends beyond accepted anchor",
        ));
    }
    let range = Range {
        count,
        blocks: Vec::new(),
        positions: Some(Positions {
            anchor: anchor.as_slice().to_vec(),
            scripts_revision: revision,
            recheck: false,
            matches: matches
                .into_iter()
                .map(|(n, hash)| (n, hash.unpack(), false))
                .collect(),
        }),
    };
    if !current(storage, start, &range)? {
        return Err(Error::runtime("obsolete filter context"));
    }
    let mut batch = storage.batch();
    if let Some(old_bytes) = storage.get(key(start))? {
        let old = decode(&old_bytes)?;
        if current(storage, start, &old)? && !recovery::repair_pending(storage)? {
            return Err(Error::runtime("cannot replace pending verified coverage"));
        }
        let old_end = bounds(start, old.count)?;
        if end > old_end {
            return Err(Error::runtime("recheck page exceeds saved range"));
        }
        batch.delete(&key(start));
        if end < old_end {
            let mut tail_end = old_end;
            if let Some(existing) = storage.get(key(end + 1))? {
                let existing = decode(&existing)?;
                tail_end = tail_end.max(bounds(end + 1, existing.count)?);
            }
            let tail = Range {
                count: tail_end - end,
                blocks: Vec::new(),
                positions: None,
            };
            batch.put(&key(end + 1), &encode(&tail)?);
        }
    }
    if !range
        .positions
        .as_ref()
        .expect("new positions")
        .matches
        .is_empty()
    {
        batch.put(&key(start), &encode(&range)?);
    }
    batch.put(
        &meta(super::super::MIN_FILTERED_BLOCK_NUMBER),
        &end.to_le_bytes(),
    );
    bump_revision(storage, &mut batch)?;
    batch.commit()
}

/// Authenticate the header first (PoW/MMR), then check the saved expectation.
/// A mismatched proof must not install membership or watched-state provenance.
pub(crate) fn check_headers<S: LightClientStorage + ?Sized>(
    storage: &S,
    headers: &[HeaderView],
) -> Result<bool> {
    let Some(first) = storage.get_earliest_matched_blocks() else {
        return Ok(true);
    };
    let range = load(storage, first.start_number)?;
    let mut valid = current(storage, first.start_number, &range)?;
    if let Some(p) = &range.positions {
        valid &= headers.iter().all(|h| {
            p.matches.iter().any(|(n, hash, _)| {
                *n == h.number() && *hash == Unpack::<[u8; 32]>::unpack(&h.hash())
            })
        });
    } else {
        valid = false;
    }
    if !valid {
        recheck(storage, first.start_number)?;
        return Err(Error::runtime(
            "proof does not match saved filter positions; refilter required",
        ));
    }
    Ok(true)
}
pub(crate) fn check_bodies<S: LightClientStorage + ?Sized>(
    storage: &S,
    blocks: &[packed::Block],
) -> Result<()> {
    let first = storage
        .get_earliest_matched_blocks()
        .ok_or_else(|| Error::runtime("missing coverage"))?;
    let range = load(storage, first.start_number)?;
    let headers: Vec<_> = blocks.iter().map(|b| b.header().into_view()).collect();
    if !check_headers(storage, &headers)? {
        return Err(Error::runtime("obsolete coverage bodies"));
    }
    let p = range
        .positions
        .as_ref()
        .ok_or_else(|| Error::runtime("unbound coverage"))?;
    let unique: HashSet<_> = headers.iter().map(|h| h.hash()).collect();
    let mut proved = true;
    for h in &headers {
        proved &= anchor_current(storage, &h.data())?;
    }
    if blocks.len() != p.matches.len() || unique.len() != blocks.len() || !proved {
        return Err(Error::runtime("incomplete or unproved coverage bodies"));
    }
    Ok(())
}

/// This flag commits with the derived rows, never with a mere proof or download.
pub(crate) fn mark_indexed<S: LightClientStorage + ?Sized>(
    storage: &S,
    batch: &mut S::Batch,
    block: &packed::Block,
) -> Result<()> {
    let header = block.header();
    let Some(first) = storage.get_earliest_matched_blocks() else {
        return Ok(());
    };
    let mut range = load(storage, first.start_number)?;
    let hash: [u8; 32] = header.calc_header_hash().unpack();
    let Some(p) = &mut range.positions else {
        return Ok(());
    };
    if let Some((n, _, indexed)) = p.matches.iter_mut().find(|(_, h, _)| *h == hash) {
        if *n != Unpack::<u64>::unpack(&header.raw().number()) {
            return Err(Error::runtime(
                "indexed body differs from expected filter position",
            ));
        }
        let view = block.clone().into_view_without_reset_header();
        if view.transactions_root() != view.calc_transactions_root()
            || view.proposals_hash() != view.calc_proposals_hash()
            || view.extra_hash() != view.calc_extra_hash().extra_hash()
            || view
                .uncles()
                .into_iter()
                .any(|u| u.proposals_hash() != u.calc_proposals_hash())
        {
            return Err(Error::runtime("indexed body differs from proved header"));
        }
        *indexed = true;
        if !current(storage, first.start_number, &range)? || !anchor_current(storage, &header)? {
            return Err(Error::runtime("indexed body has obsolete coverage context"));
        }
        member(batch, &header);
        batch.put(&key(first.start_number), &encode(&range)?);
    }
    Ok(())
}
pub(crate) fn check_complete<S: LightClientStorage + ?Sized>(
    storage: &S,
    start: u64,
    end: u64,
) -> Result<()> {
    let first = storage
        .get_earliest_matched_blocks()
        .ok_or_else(|| Error::runtime("missing completed range"))?;
    if first.start_number != start {
        return Err(Error::runtime("coverage completion is out of order"));
    }
    let range = load(storage, start)?;
    if bounds(start, range.count)? != end || !current(storage, start, &range)? {
        return Err(Error::runtime(
            "cannot complete unbound or obsolete coverage",
        ));
    }
    let p = range.positions.as_ref().expect("checked positions");
    if p.matches.is_empty() {
        return Err(Error::runtime("empty persisted positional coverage"));
    }
    for (n, hash, indexed) in &p.matches {
        if !indexed || storage.get(member_key(*n))?.as_deref() != Some(hash.as_slice()) {
            return Err(Error::runtime(
                "coverage has an unindexed/unproved position",
            ));
        }
    }
    Ok(())
}

pub(crate) fn pending<S: StorageBackend + ?Sized>(storage: &S) -> Result<bool> {
    let prefix = meta(super::super::MATCHED_FILTER_BLOCKS_KEY);
    let select = prefix.clone();
    Ok(!storage
        .try_collect_iterator(
            IteratorStart::From(prefix),
            IteratorDirection::Forward,
            Box::new(move |k| k.starts_with(&select)),
            Box::new(|_, v| Some(v.to_vec())),
            1,
        )?
        .is_empty())
}

pub(crate) fn recheck_limit<S: LightClientStorage + ?Sized>(
    storage: &S,
    start: u64,
    mut limit: usize,
) -> Result<usize> {
    let prefix = meta(super::super::MATCHED_FILTER_BLOCKS_KEY);
    let select = prefix.clone();
    let rows = storage.try_collect_iterator(
        IteratorStart::From(key(start)),
        IteratorDirection::Forward,
        Box::new(move |k| k.starts_with(&select)),
        Box::new(|_, v| Some(v.to_vec())),
        2,
    )?;
    for row in rows {
        let number = row
            .key
            .get(prefix.len()..)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_be_bytes)
            .ok_or_else(|| Error::runtime("invalid recheck range key"))?;
        if number == start {
            let range = decode(&row.value)?;
            limit = limit.min(usize::try_from(range.count).unwrap_or(usize::MAX));
        } else {
            limit = limit.min(usize::try_from(number - start).unwrap_or(usize::MAX));
            break;
        }
    }
    Ok(limit)
}
pub(crate) fn restorable_blocks<S: LightClientStorage + ?Sized>(
    storage: &S,
    first: &crate::storage::MatchedBlocks,
) -> Result<Vec<(packed::Byte32, bool)>> {
    cached_matches(storage, first)?.ok_or_else(|| Error::runtime("unbound filter range"))
}

pub(crate) fn cached_matches<S: LightClientStorage + ?Sized>(
    storage: &S,
    first: &crate::storage::MatchedBlocks,
) -> Result<Option<Vec<(packed::Byte32, bool)>>> {
    let range = load(storage, first.start_number)?;
    if !current(storage, first.start_number, &range)? {
        return Ok(None);
    }
    let p = range.positions.as_ref().expect("current positions");
    let tip = storage.get_tip_header();
    let mut blocks = Vec::new();
    for (number, hash, _) in &p.matches {
        let hash: packed::Byte32 = hash.pack();
        let proved = if tip.calc_header_hash() == hash
            && Unpack::<u64>::unpack(&tip.raw().number()) == *number
        {
            true
        } else if let Some(bytes) = storage.get(Key::BlockHash(&hash).into_vec())? {
            let header_size = packed::Header::default().as_slice().len();
            let header = bytes
                .get(..header_size)
                .and_then(|b| packed::Header::from_slice(b).ok());
            if let Some(header) = header {
                header.calc_header_hash() == hash
                    && Unpack::<u64>::unpack(&header.raw().number()) == *number
                    && anchor_current(storage, &header)?
            } else {
                false
            }
        } else {
            false
        };
        blocks.push((hash, proved));
    }
    Ok(Some(blocks))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod format_tests {
    use super::*;
    #[test]
    fn positional_frames_are_disjoint_from_every_legacy_hash_prefix() {
        let mut hash = [0u8; 32];
        hash[..MAGIC.len()].copy_from_slice(MAGIC);
        let legacy = Range {
            count: 1,
            blocks: vec![(hash.pack(), true)],
            positions: None,
        };
        let decoded = decode(&encode(&legacy).unwrap()).unwrap();
        assert!(decoded.positions.is_none());
        assert_eq!(decoded.blocks[0].0, hash.pack());
        for count in 1..100u64 {
            let range = Range {
                count,
                blocks: Vec::new(),
                positions: Some(Positions {
                    anchor: packed::Header::default().as_slice().to_vec(),
                    scripts_revision: 42,
                    recheck: false,
                    matches: (1..=count)
                        .map(|n| (n, [n as u8; 32], n % 2 == 0))
                        .collect(),
                }),
            };
            let bytes = encode(&range).unwrap();
            assert!(!(bytes.len() - 8).is_multiple_of(33));
            let recovered = decode(&bytes).unwrap().positions.unwrap();
            assert_eq!(recovered.matches, range.positions.unwrap().matches);
            assert_eq!(recovered.scripts_revision, 42);
            let mut malformed = bytes.clone();
            malformed[8 + MAGIC.len()..8 + MAGIC.len() + 8].fill(255);
            assert!(decode(&malformed).is_err());
        }
    }
}
