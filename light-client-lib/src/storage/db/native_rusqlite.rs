use super::super::{
    extract_raw_data, parse_matched_blocks, BlockNumber, Byte32, CellIndex, CellType, CpIndex, Key,
    KeyPrefix, MatchedBlock, MatchedBlocks, Script, FILTER_SCRIPTS_KEY, MATCHED_FILTER_BLOCKS_KEY,
    MIN_FILTERED_BLOCK_NUMBER,
};
use crate::{
    error::Result,
    storage::{ScriptStatus, ScriptType, SetScriptsCommand, TxIndex},
};
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellProvider, CellStatus},
        HeaderView, TransactionInfo,
    },
    packed::{self, CellOutput, Header, OutPoint},
    prelude::*,
};

use parking_lot::ReentrantMutex;
use rusqlite::{params, Connection};
use std::{cell::RefCell, path::Path, sync::Arc};

#[derive(Clone)]
pub struct Storage {
    pub(crate) conn: Arc<ReentrantMutex<RefCell<Connection>>>,
}
pub struct KV {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Copy)]
pub enum CursorDirection {
    Ascending,
    Descending,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(raw_path: P) -> Self {
        if !raw_path.as_ref().exists() {
            std::fs::create_dir_all(raw_path.as_ref())
                .expect("Unable to creatr directory for database");
        }
        let path = raw_path.as_ref().join("light-client.db");

        let conn = Connection::open(path).expect("Unable to open database");
        conn.execute_batch(
            r"
        CREATE TABLE IF NOT EXISTS data (
            key BLOB PRIMARY KEY,
            value BLOB
        );
        ",
        )
        .expect("Unable to initialize database and create table");
        Self {
            conn: Arc::new(ReentrantMutex::new(RefCell::new(conn))),
        }
    }

    pub fn collect_iterator(
        &self,
        start_key_bound: &[u8],
        order: CursorDirection,
        take_while: impl Fn(&[u8]) -> bool,
        filter_map: impl Fn(&[u8], &[u8]) -> Option<KV>,
        limit: usize,
        skip: usize,
    ) -> rusqlite::Result<Vec<KV>> {
        let lock_guard = self.conn.lock();
        let conn = lock_guard.borrow();
        let sql = match order {
            CursorDirection::Ascending => {
                "SELECT key, value FROM data WHERE key >= ?1 ORDER BY key ASC"
            }
            CursorDirection::Descending => {
                "SELECT key, value FROM data WHERE key <= ?1 ORDER BY key DESC"
            }
        };

        let mut stmt = conn.prepare(sql)?;
        let mut rows = stmt.query(params![start_key_bound])?;

        let mut results = Vec::new();
        let mut skipped = 0;

        while let Some(row) = rows.next()? {
            let key: Vec<u8> = row.get(0)?;
            let value: Vec<u8> = row.get(1)?;

            if !take_while(&key) {
                break;
            }

            if let Some(kv) = filter_map(&key, &value) {
                if skipped < skip {
                    skipped += 1;
                    continue;
                }

                results.push(kv);

                if results.len() >= limit {
                    break;
                }
            }
        }

        Ok(results)
    }

    pub fn batch(&self) -> Batch {
        Batch {
            db: self.conn.clone(),
            add: vec![],
            delete: vec![],
        }
    }

    pub fn put<K, V>(&self, key: K, value: V) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let lock_guard = self.conn.lock();
        let mut guard = lock_guard.borrow_mut();
        let tx = guard.transaction()?;
        if tx.query_one(
            "SELECT COUNT(*) FROM data WHERE key = ?1",
            [key.as_ref().to_vec()],
            |x| Ok(x.get::<_, isize>(0)?),
        )? == 0
        {
            tx.execute(
                "INSERT INTO data (key, value) VALUES (?1, ?2)",
                [key.as_ref().to_vec(), value.as_ref().to_vec()],
            )?;
        } else {
            tx.execute(
                "UPDATE data SET value = ?2 WHERE key = ?1",
                [key.as_ref().to_vec(), value.as_ref().to_vec()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>> {
        let lock_guard = self.conn.lock();
        let guard = lock_guard.borrow();
        match guard.query_one(
            "SELECT value FROM data WHERE key = ?1",
            [key.as_ref().to_vec()],
            |row| Ok(row.get::<_, Vec<u8>>(0)?),
        ) {
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            s => Ok(s.map(|v| Some(v))?),
        }
    }
    #[allow(clippy::needless_lifetimes)]
    pub fn get_pinned<K>(&self, key: K) -> Result<Option<Vec<u8>>>
    where
        K: AsRef<[u8]>,
    {
        self.get(key)
    }

    pub fn delete<K: AsRef<[u8]>>(&self, key: K) -> Result<()> {
        let lock_guard = self.conn.lock();
        let guard = lock_guard.borrow();
        guard.execute("DELETE FROM data WHERE key = ?1", [key.as_ref().to_vec()])?;
        Ok(())
    }

    pub fn is_filter_scripts_empty(&self) -> bool {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        self.collect_iterator(
            &key_prefix,
            CursorDirection::Ascending,
            |key| key.starts_with(&key_prefix),
            |key, value| {
                Some(KV {
                    key: key.to_vec(),
                    value: value.to_vec(),
                })
            },
            1,
            0,
        )
        .unwrap()
        .is_empty()
    }

    pub fn get_filter_scripts(&self) -> Vec<ScriptStatus> {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();

        self.collect_iterator(
            &key_prefix,
            CursorDirection::Ascending,
            |key| key.starts_with(&key_prefix),
            |key, value| {
                Some(KV {
                    key: key.to_vec(),
                    value: value.to_vec(),
                })
            },
            usize::MAX,
            0,
        )
        .unwrap()
        .into_iter()
        .map(|kv| (kv.key, kv.value))
        .map(|(key, value)| {
            let script =
                Script::from_slice(&key[key_prefix.len()..key.len() - 1]).expect("stored Script");
            let script_type = match key[key.len() - 1] {
                0 => ScriptType::Lock,
                1 => ScriptType::Type,
                _ => panic!("invalid script type"),
            };
            let block_number = BlockNumber::from_be_bytes(
                AsRef::<[u8]>::as_ref(&value)
                    .try_into()
                    .expect("stored BlockNumber"),
            );
            ScriptStatus {
                script,
                script_type,
                block_number,
            }
        })
        .collect()
    }

    pub fn update_filter_scripts(&self, scripts: Vec<ScriptStatus>, command: SetScriptsCommand) {
        let mut should_filter_genesis_block = false;
        let mut batch = self.batch();
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();

        match command {
            SetScriptsCommand::All => {
                should_filter_genesis_block = scripts.iter().any(|ss| ss.block_number == 0);

                let remove_keys = self
                    .collect_iterator(
                        &key_prefix,
                        CursorDirection::Ascending,
                        |x| x.starts_with(&key_prefix),
                        |k, v| {
                            Some(KV {
                                key: k.to_vec(),
                                value: v.to_vec(),
                            })
                        },
                        usize::MAX,
                        0,
                    )
                    .unwrap()
                    .into_iter()
                    .map(|x| x.key)
                    .collect();

                batch.delete_many(remove_keys).unwrap();

                for ss in scripts {
                    let key = [
                        key_prefix.as_ref(),
                        ss.script.as_slice(),
                        match ss.script_type {
                            ScriptType::Lock => &[0],
                            ScriptType::Type => &[1],
                        },
                    ]
                    .concat();
                    batch
                        .put(key, ss.block_number.to_be_bytes())
                        .expect("batch put should be ok");
                }
            }
            SetScriptsCommand::Partial => {
                if scripts.is_empty() {
                    return;
                }
                let min_script_block_number = scripts.iter().map(|ss| ss.block_number).min();
                should_filter_genesis_block = min_script_block_number == Some(0);

                for ss in scripts {
                    let key = [
                        key_prefix.as_ref(),
                        ss.script.as_slice(),
                        match ss.script_type {
                            ScriptType::Lock => &[0],
                            ScriptType::Type => &[1],
                        },
                    ]
                    .concat();
                    batch
                        .put(key, ss.block_number.to_be_bytes())
                        .expect("batch put should be ok");
                }
            }
            SetScriptsCommand::Delete => {
                if scripts.is_empty() {
                    return;
                }

                for ss in scripts {
                    let key = [
                        key_prefix.as_ref(),
                        ss.script.as_slice(),
                        match ss.script_type {
                            ScriptType::Lock => &[0],
                            ScriptType::Type => &[1],
                        },
                    ]
                    .concat();
                    batch.delete(key).expect("batch delete should be ok");
                }
            }
        }

        batch.commit().expect("batch commit should be ok");

        self.update_min_filtered_block_number_by_scripts();
        self.clear_matched_blocks();

        if should_filter_genesis_block {
            let block = self.get_genesis_block();
            self.filter_block(block);
        }
    }

    fn update_min_filtered_block_number_by_scripts(&self) {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();

        let value = self
            .collect_iterator(
                &key_prefix,
                CursorDirection::Ascending,
                |x| x.starts_with(&key_prefix),
                |k, v| {
                    Some(KV {
                        key: k.to_vec(),
                        value: v.to_vec(),
                    })
                },
                usize::MAX,
                0,
            )
            .unwrap();

        let min_block_number = value
            .into_iter()
            .map(|kv| (kv.key, kv.value))
            .map(|(_key, value)| {
                BlockNumber::from_be_bytes(
                    AsRef::<[u8]>::as_ref(&value)
                        .try_into()
                        .expect("stored BlockNumber"),
                )
            })
            .min();

        if let Some(n) = min_block_number {
            self.update_min_filtered_block_number(n);
        }
    }

    // get scripts hash that should be filtered below the given block number
    pub fn get_scripts_hash(&self, block_number: BlockNumber) -> Vec<Byte32> {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();

        let value = self
            .collect_iterator(
                &key_prefix,
                CursorDirection::Ascending,
                |x| x.starts_with(&key_prefix),
                |k, v| {
                    Some(KV {
                        key: k.to_vec(),
                        value: v.to_vec(),
                    })
                },
                usize::MAX,
                0,
            )
            .unwrap();

        value
            .into_iter()
            .map(|kv| (kv.key, kv.value))
            .filter_map(|(key, value)| {
                let stored_block_number = BlockNumber::from_be_bytes(
                    AsRef::<[u8]>::as_ref(&value)
                        .try_into()
                        .expect("stored BlockNumber"),
                );
                if stored_block_number < block_number {
                    let script = Script::from_slice(&key[key_prefix.len()..key.len() - 1])
                        .expect("stored Script");
                    Some(script.calc_script_hash())
                } else {
                    None
                }
            })
            .collect()
    }

    fn clear_matched_blocks(&self) {
        let key_prefix: Vec<u8> = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();

        let mut batch = self.batch();

        let value = self
            .collect_iterator(
                &key_prefix,
                CursorDirection::Ascending,
                |x| x.starts_with(&key_prefix),
                |k, v| {
                    Some(KV {
                        key: k.to_vec(),
                        value: v.to_vec(),
                    })
                },
                usize::MAX,
                0,
            )
            .unwrap()
            .into_iter()
            .map(|x| x.key)
            .collect();
        batch.delete_many(value).unwrap();
        batch.commit().unwrap();
    }

    fn get_matched_blocks(&self, direction: CursorDirection) -> Option<MatchedBlocks> {
        let key_prefix = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();
        let iter_from = match direction {
            CursorDirection::Ascending => key_prefix.clone(),
            CursorDirection::Descending => {
                let mut key = key_prefix.clone();
                key.extend(u64::MAX.to_be_bytes());
                key
            }
        };

        let value = self
            .collect_iterator(
                &iter_from,
                direction,
                |x| x.starts_with(&key_prefix),
                |k, v| {
                    Some(KV {
                        key: k.to_vec(),
                        value: v.to_vec(),
                    })
                },
                1,
                0,
            )
            .unwrap();

        value
            .into_iter()
            .map(|kv| (kv.key, kv.value))
            .map(|(key, value)| {
                let mut u64_bytes = [0u8; 8];
                u64_bytes.copy_from_slice(&key[key_prefix.len()..]);
                let start_number = u64::from_be_bytes(u64_bytes);
                let (blocks_count, raw_blocks) = parse_matched_blocks(&value);
                let blocks = raw_blocks
                    .into_iter()
                    .map(|(hash, proved)| MatchedBlock { hash, proved })
                    .collect();
                MatchedBlocks {
                    start_number,
                    blocks_count,
                    blocks,
                }
            })
            .next()
    }

    pub fn get_earliest_matched_blocks(&self) -> Option<MatchedBlocks> {
        self.get_matched_blocks(CursorDirection::Ascending)
    }

    pub fn get_latest_matched_blocks(&self) -> Option<MatchedBlocks> {
        self.get_matched_blocks(CursorDirection::Descending)
    }

    pub fn get_check_points(&self, start_index: CpIndex, limit: usize) -> Vec<Byte32> {
        let start_key = Key::CheckPointIndex(start_index).into_vec();
        let key_prefix = [KeyPrefix::CheckPointIndex as u8];

        let value = self
            .collect_iterator(
                &start_key,
                CursorDirection::Ascending,
                |x| x.starts_with(&key_prefix),
                |k, v| {
                    Some(KV {
                        key: k.to_vec(),
                        value: v.to_vec(),
                    })
                },
                limit,
                0,
            )
            .unwrap();

        value
            .into_iter()
            .map(|kv| (kv.key, kv.value))
            .map(|(_key, value)| Byte32::from_slice(&value).expect("stored block filter hash"))
            .collect()
    }

    pub fn update_block_number(&self, block_number: BlockNumber) {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let mut batch = self.batch();

        let value = self
            .collect_iterator(
                &key_prefix,
                CursorDirection::Ascending,
                |x| x.starts_with(&key_prefix),
                |k, v| {
                    Some(KV {
                        key: k.to_vec(),
                        value: v.to_vec(),
                    })
                },
                usize::MAX,
                0,
            )
            .unwrap();

        value
            .into_iter()
            .map(|kv| (kv.key, kv.value))
            .for_each(|(key, value)| {
                let stored_block_number = BlockNumber::from_be_bytes(
                    AsRef::<[u8]>::as_ref(&value)
                        .try_into()
                        .expect("stored BlockNumber"),
                );
                if stored_block_number < block_number {
                    batch
                        .put(key, block_number.to_be_bytes())
                        .expect("batch put should be ok")
                }
            });
        batch.commit().expect("batch commit should be ok");
    }

    /// Rollback filtered block data to specified block number
    ///
    /// N.B. The specified block will be removed.
    pub fn rollback_to_block(&self, to_number: BlockNumber) {
        let scripts = self.get_filter_scripts();
        let mut batch = self.batch();

        for ss in scripts {
            if ss.block_number >= to_number {
                let script = ss.script;
                let mut key_prefix = vec![match ss.script_type {
                    ScriptType::Lock => KeyPrefix::TxLockScript as u8,
                    ScriptType::Type => KeyPrefix::TxTypeScript as u8,
                }];
                key_prefix.extend_from_slice(&extract_raw_data(&script));
                let mut start_key = key_prefix.clone();
                start_key.extend_from_slice(BlockNumber::MAX.to_be_bytes().as_ref());
                let key_prefix_len = key_prefix.len();

                let value = self
                    .collect_iterator(
                        &key_prefix,
                        CursorDirection::Descending,
                        |raw_key: &[u8]| {
                            raw_key.starts_with(&key_prefix)
                                && BlockNumber::from_be_bytes(
                                    raw_key[key_prefix_len..key_prefix_len + 8]
                                        .try_into()
                                        .expect("stored BlockNumber"),
                                ) >= to_number
                        },
                        |k, v| {
                            Some(KV {
                                key: k.to_vec(),
                                value: v.to_vec(),
                            })
                        },
                        usize::MAX,
                        0,
                    )
                    .unwrap();

                for (key, value) in value.into_iter().map(|kv| (kv.key, kv.value)) {
                    let block_number = BlockNumber::from_be_bytes(
                        key[key_prefix_len..key_prefix_len + 8]
                            .try_into()
                            .expect("stored BlockNumber"),
                    );
                    log::debug!("rollback {}", block_number);
                    let tx_index = TxIndex::from_be_bytes(
                        key[key_prefix_len + 8..key_prefix_len + 12]
                            .try_into()
                            .expect("stored TxIndex"),
                    );
                    let cell_index = CellIndex::from_be_bytes(
                        key[key_prefix_len + 12..key_prefix_len + 16]
                            .try_into()
                            .expect("stored CellIndex"),
                    );
                    let tx_hash = packed::Byte32Reader::from_slice_should_be_ok(&value).to_entity();
                    if key[key_prefix_len + 16] == 0 {
                        let (_, _, tx) = self
                            .get_transaction(&tx_hash)
                            .expect("stored transaction history");
                        let input = tx.raw().inputs().get(cell_index as usize).unwrap();
                        if let Some((
                            generated_by_block_number,
                            generated_by_tx_index,
                            _previous_tx,
                        )) = self.get_transaction(&input.previous_output().tx_hash())
                        {
                            let key = match ss.script_type {
                                ScriptType::Lock => Key::CellLockScript(
                                    &script,
                                    generated_by_block_number,
                                    generated_by_tx_index,
                                    input.previous_output().index().unpack(),
                                ),
                                ScriptType::Type => Key::CellTypeScript(
                                    &script,
                                    generated_by_block_number,
                                    generated_by_tx_index,
                                    input.previous_output().index().unpack(),
                                ),
                            };
                            batch
                                .put_kv(key, input.previous_output().tx_hash().as_slice())
                                .expect("batch put should be ok");
                        };
                        // delete tx history
                        let key = match ss.script_type {
                            ScriptType::Lock => Key::TxLockScript(
                                &script,
                                block_number,
                                tx_index,
                                cell_index,
                                CellType::Input,
                            ),
                            ScriptType::Type => Key::TxTypeScript(
                                &script,
                                block_number,
                                tx_index,
                                cell_index,
                                CellType::Input,
                            ),
                        }
                        .into_vec();
                        batch.delete(key).expect("batch delete should be ok");
                    } else {
                        // delete utxo
                        let key = match ss.script_type {
                            ScriptType::Lock => {
                                Key::CellLockScript(&script, block_number, tx_index, cell_index)
                            }
                            ScriptType::Type => {
                                Key::CellTypeScript(&script, block_number, tx_index, cell_index)
                            }
                        }
                        .into_vec();
                        batch.delete(key).expect("batch delete should be ok");

                        // delete tx history
                        let key = match ss.script_type {
                            ScriptType::Lock => Key::TxLockScript(
                                &script,
                                block_number,
                                tx_index,
                                cell_index,
                                CellType::Output,
                            ),
                            ScriptType::Type => Key::TxTypeScript(
                                &script,
                                block_number,
                                tx_index,
                                cell_index,
                                CellType::Output,
                            ),
                        }
                        .into_vec();
                        batch.delete(key).expect("batch delete should be ok");
                    };
                }

                // update script filter block number
                {
                    let mut key = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
                    key.extend_from_slice(script.as_slice());
                    key.extend_from_slice(match ss.script_type {
                        ScriptType::Lock => &[0],
                        ScriptType::Type => &[1],
                    });
                    let value = to_number.to_be_bytes().to_vec();
                    batch.put(key, value).expect("batch put should be ok");
                }
            }
        }
        // we should also sync block filters again
        if self.get_min_filtered_block_number() >= to_number {
            batch
                .put(
                    Key::Meta(MIN_FILTERED_BLOCK_NUMBER).into_vec(),
                    to_number.saturating_sub(1).to_le_bytes(),
                )
                .expect("batch put should be ok");
        }

        batch.commit().expect("batch commit should be ok");
    }
}

pub struct Batch {
    add: Vec<(Vec<u8>, Vec<u8>)>,
    delete: Vec<Vec<u8>>,
    db: Arc<ReentrantMutex<RefCell<Connection>>>,
}

impl Batch {
    pub fn put_kv<K: Into<Vec<u8>>, V: Into<Vec<u8>>>(&mut self, key: K, value: V) -> Result<()> {
        self.add.push((key.into(), value.into()));
        Ok(())
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<()> {
        self.add
            .push((key.as_ref().to_vec(), value.as_ref().to_vec()));
        Ok(())
    }

    pub fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<()> {
        self.delete.push(key.as_ref().to_vec());
        Ok(())
    }

    pub fn delete_many(&mut self, keys: Vec<Vec<u8>>) -> Result<()> {
        let lock_guard = self.db.lock();
        let guard = lock_guard.borrow();
        let mut stmt = guard.prepare("DELETE FROM data WHERE key = ?1")?;

        for item in keys.into_iter() {
            stmt.execute([item])?;
        }
        Ok(())
    }

    pub fn commit(self) -> Result<()> {
        let lock_guard = self.db.lock();
        let mut guard = lock_guard.borrow_mut();
        if !self.add.is_empty() {
            for (key, value) in self.add.into_iter() {
                let tx = guard.transaction()?;
                if tx.query_one(
                    "SELECT COUNT(*) FROM data WHERE key = ?1",
                    [key.clone()],
                    |x| Ok(x.get::<_, isize>(0)?),
                )? == 0
                {
                    tx.execute(
                        "INSERT INTO data (key, value) VALUES (?1, ?2)",
                        [key, value],
                    )?;
                } else {
                    tx.execute("UPDATE data SET value = ?2 WHERE key = ?1", [key, value])?;
                }
                tx.commit()?;
            }
        }

        if !self.delete.is_empty() {
            let mut stmt = guard.prepare("DELETE FROM data WHERE key = ?1")?;
            for key in self.delete.into_iter() {
                stmt.execute([key])?;
            }
        }

        Ok(())
    }
}

impl CellProvider for Storage {
    // assume all cells are live and load data eagerly
    fn cell(&self, out_point: &OutPoint, _eager_load: bool) -> CellStatus {
        if let Some((block_number, tx_index, tx)) = self.get_transaction(&out_point.tx_hash()) {
            let block_hash = Byte32::from_slice(
                &self
                    .get(Key::BlockNumber(block_number).into_vec())
                    .expect("db get should be ok")
                    .expect("stored block number / hash mapping"),
            )
            .expect("stored block hash should be OK");

            let header = Header::from_slice(
                &self
                    .get(Key::BlockHash(&block_hash).into_vec())
                    .expect("db get should be ok")
                    .expect("stored block hash / header mapping")[..Header::TOTAL_SIZE],
            )
            .expect("stored header should be OK")
            .into_view();

            let output_index = out_point.index().unpack();
            let tx = tx.into_view();
            if let Some(cell_output) = tx.outputs().get(output_index) {
                let output_data = tx
                    .outputs_data()
                    .get(output_index)
                    .expect("output_data's index should be same as output")
                    .raw_data();
                let output_data_data_hash = CellOutput::calc_data_hash(&output_data);
                let cell_meta = CellMeta {
                    out_point: out_point.clone(),
                    cell_output,
                    transaction_info: Some(TransactionInfo {
                        block_hash,
                        block_epoch: header.epoch(),
                        block_number,
                        index: tx_index as usize,
                    }),
                    data_bytes: output_data.len() as u64,
                    mem_cell_data: Some(output_data),
                    mem_cell_data_hash: Some(output_data_data_hash),
                };
                return CellStatus::Live(cell_meta);
            }
        }
        CellStatus::Unknown
    }
}

impl CellDataProvider for Storage {
    // we load all cells data eagerly in Storage's CellProivder impl
    fn get_cell_data(&self, _out_point: &OutPoint) -> Option<Bytes> {
        unreachable!()
    }

    fn get_cell_data_hash(&self, _out_point: &OutPoint) -> Option<Byte32> {
        unreachable!()
    }
}

impl HeaderProvider for Storage {
    fn get_header(&self, hash: &Byte32) -> Option<HeaderView> {
        self.get(Key::BlockHash(hash).into_vec())
            .map(|v| {
                v.map(|v| {
                    Header::from_slice(&v[..Header::TOTAL_SIZE])
                        .expect("stored Header")
                        .into_view()
                })
            })
            .expect("db get should be ok")
    }
}
