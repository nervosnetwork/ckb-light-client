use super::*;
const BODY: &str = "ORDINAL_BODY_V2:";
fn body_key(hash: &packed::Byte32) -> Vec<u8> {
    let mut key = meta(BODY);
    key.extend(hash.as_slice());
    key
}

pub(crate) fn queue_ordinal_body<S: StorageBackend + ?Sized>(
    storage: &S,
    header: &packed::Header,
) -> Result<()> {
    if !anchor_current(storage, header)? {
        return Err(Error::runtime(
            "ordinal body inclusion is no longer current",
        ));
    }
    storage.put(
        body_key(&header.calc_header_hash()),
        header.as_slice().to_vec(),
    )
}
pub(crate) fn ordinal_bodies<S: StorageBackend + ?Sized>(
    storage: &S,
) -> Result<Vec<packed::Byte32>> {
    let prefix = meta(BODY);
    let select = prefix.clone();
    let rows = storage.try_collect_iterator(
        IteratorStart::From(prefix),
        IteratorDirection::Forward,
        Box::new(move |key| key.starts_with(&select)),
        Box::new(|_, value| Some(value.to_vec())),
        usize::MAX,
    )?;
    let mut pending = Vec::new();
    for row in rows {
        let header = packed::Header::from_slice(&row.value)
            .map_err(|_| Error::runtime("invalid pending ordinal header"))?;
        if anchor_current(storage, &header)? {
            pending.push(header.calc_header_hash());
        } else {
            storage.delete(&row.key)?;
        }
    }
    Ok(pending)
}
pub(crate) fn needs_ordinal_body<S: StorageBackend + ?Sized>(
    storage: &S,
    hash: &packed::Byte32,
) -> Result<bool> {
    Ok(storage.get(body_key(hash))?.is_some())
}

/// The caller validates the complete body against its committed header first.
/// Bind positions only: filtering historical outputs here could resurrect spends.
pub(crate) fn recover_ordinals<S: StorageBackend + ?Sized>(
    storage: &S,
    block: &packed::Block,
) -> Result<()> {
    let hash = block.calc_header_hash();
    let Some(header) = storage.get(body_key(&hash))? else {
        return Ok(());
    };
    if header.as_slice() != block.header().as_slice() || !anchor_current(storage, &block.header())?
    {
        return Err(Error::runtime("stale ordinal body"));
    }
    let mut batch = storage.batch();
    for (index, tx) in block.transactions().into_iter().enumerate() {
        let tx_hash = tx.calc_tx_hash();
        let Some(old) = transaction(storage, &tx_hash)? else {
            continue;
        };
        if old.header.calc_header_hash() != hash {
            continue;
        }
        let number: u64 = block.header().raw().number().unpack();
        batch.put(
            &Key::TxHash(&tx_hash).into_vec(),
            &Vec::<u8>::from(Value::Transaction(number, index as u32, &tx)),
        );
        bind(&mut batch, &tx, &block.header(), true, index as u32);
    }
    batch.delete(&body_key(&hash));
    batch.commit()
}
