use std::{cell::RefCell, path::Path, sync::atomic::AtomicBool};

use super::super::{
    BlockNumber, Byte32, CellType, Script, ScriptStatus, ScriptType, SetScriptsCommand,
};
use anyhow::{anyhow, bail, Context};

use crate::storage::db::StorageBatchRelatedOperations;
use crate::storage::db::{StorageGeneralOperations, StorageGetPinnedRelatedOperations};
use ckb_types::{
    core::{
        cell::{CellMeta, CellStatus},
        HeaderView, TransactionInfo,
    },
    packed::{self, CellOutput, Header, OutPoint},
    prelude::{Entity, FromSliceShouldBeOk, IntoHeaderView, IntoTransactionView, Reader, Unpack},
};
pub use idb::CursorDirection;
use light_client_db_common::{
    idb_cursor_direction_to_ckb, read_command_payload, write_command_with_payload,
    DbCommandRequest, DbCommandResponse, InputCommand, OutputCommand, KV,
};
use log::debug;

use crate::{
    error::{Error, Result},
    storage::{
        db::{GeneralDirection, StorageHighLevelOperations},
        extract_raw_data, parse_matched_blocks, CellIndex, CpIndex, Key, KeyPrefix, MatchedBlock,
        MatchedBlocks, TxIndex, FILTER_SCRIPTS_KEY, MATCHED_FILTER_BLOCKS_KEY,
        MIN_FILTERED_BLOCK_NUMBER,
    },
};
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue};
use web_sys::js_sys::{Atomics, Int32Array, SharedArrayBuffer, Uint8Array};
enum CommandRequestWithTakeWhileAndFilterMap {
    Read {
        keys: Vec<Vec<u8>>,
    },
    Put {
        kvs: Vec<KV>,
    },
    Delete {
        keys: Vec<Vec<u8>>,
    },
    #[allow(clippy::type_complexity)]
    Iterator {
        start_key_bound: Vec<u8>,
        order: CursorDirection,
        take_while: Box<dyn Fn(&[u8]) -> bool + Send + 'static>,
        filter_map: Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static>,
        limit: usize,
        skip: usize,
    },
    #[allow(clippy::type_complexity)]
    IteratorKey {
        start_key_bound: Vec<u8>,
        order: CursorDirection,
        take_while: Box<dyn Fn(&[u8]) -> bool + Send + 'static>,
        filter_map: Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static>,
        limit: usize,
        skip: usize,
    },
}

thread_local! {
    static INPUT_BUFFER: RefCell<Option<SharedArrayBuffer>> = const { RefCell::new(None) };
    static OUTPUT_BUFFER: RefCell<Option<SharedArrayBuffer>> = const { RefCell::new(None) };
}
#[wasm_bindgen]
/// Set `SharedArrayBuffer` used for communicating with light client worker. This must be called before executing `main_loop`
/// input - The buffer used for sending data from light client worker to db worker
/// output - The buffer used for sending data from db worker to light client worker
pub fn set_shared_array(input: JsValue, output: JsValue) {
    console_error_panic_hook::set_once();
    INPUT_BUFFER.with(|v| {
        *v.borrow_mut() = Some(input.dyn_into().unwrap());
    });
    OUTPUT_BUFFER.with(|v| {
        *v.borrow_mut() = Some(output.dyn_into().unwrap());
    });
}

#[derive(Clone)]
/// The channel used for communicating with db worker
struct CommunicationChannel {
    input_i32_arr: Int32Array,
    input_u8_arr: Uint8Array,
    output_i32_arr: Int32Array,
    output_u8_arr: Uint8Array,
}

impl CommunicationChannel {
    /// Create a [`crate::storage::db::browser::CommunicationChannel`] from global stored buffers
    fn prepare_from_global() -> Self {
        let (input_i32_arr, input_u8_arr) = INPUT_BUFFER.with(|x| {
            let binding = x.borrow();
            let buf = binding.as_ref().unwrap();
            (Int32Array::new(buf), Uint8Array::new(buf))
        });
        let (output_i32_arr, output_u8_arr) = OUTPUT_BUFFER.with(|x| {
            let binding = x.borrow();
            let buf = binding.as_ref().unwrap();
            (Int32Array::new(buf), Uint8Array::new(buf))
        });
        Self {
            input_i32_arr,
            input_u8_arr,
            output_i32_arr,
            output_u8_arr,
        }
    }
    /// Open the database
    fn open_database(&self, store_name: &str) {
        let CommunicationChannel {
            input_i32_arr,
            input_u8_arr,
            output_i32_arr,
            output_u8_arr,
        } = &self;
        output_i32_arr.set_index(0, InputCommand::Waiting as i32);
        write_command_with_payload(
            InputCommand::OpenDatabase as i32,
            store_name,
            input_i32_arr,
            input_u8_arr,
        )
        .with_context(|| anyhow!("Failed to write db command"))
        .unwrap();
        Atomics::wait(output_i32_arr, 0, OutputCommand::Waiting as i32).unwrap();
        let output_cmd = OutputCommand::try_from(output_i32_arr.get_index(0)).unwrap();
        match output_cmd {
            OutputCommand::OpenDatabaseResponse => {
                DB_INITIALIZED.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            OutputCommand::Error => panic!(
                "{}",
                read_command_payload::<String>(output_i32_arr, output_u8_arr).unwrap()
            ),
            OutputCommand::RequestTakeWhile
            | OutputCommand::Waiting
            | OutputCommand::DbResponse
            | OutputCommand::RequestFilterMap => {
                unreachable!()
            }
        }
    }

    /// Executa a database command, retriving the response (or error)
    /// cmd: The command
    fn dispatch_database_command(
        &self,
        cmd: CommandRequestWithTakeWhileAndFilterMap,
    ) -> anyhow::Result<DbCommandResponse> {
        let (new_cmd, take_while, filter_map) = match cmd {
            CommandRequestWithTakeWhileAndFilterMap::Read { keys } => {
                (DbCommandRequest::Read { keys }, None, None)
            }
            CommandRequestWithTakeWhileAndFilterMap::Put { kvs } => {
                (DbCommandRequest::Put { kvs }, None, None)
            }
            CommandRequestWithTakeWhileAndFilterMap::Delete { keys } => {
                (DbCommandRequest::Delete { keys }, None, None)
            }
            CommandRequestWithTakeWhileAndFilterMap::Iterator {
                start_key_bound,
                order,
                take_while,
                filter_map,
                limit,
                skip,
            } => (
                DbCommandRequest::Iterator {
                    start_key_bound,
                    order: idb_cursor_direction_to_ckb(order),
                    limit,
                    skip,
                },
                Some(take_while),
                Some(filter_map),
            ),
            CommandRequestWithTakeWhileAndFilterMap::IteratorKey {
                start_key_bound,
                order,
                take_while,
                filter_map,
                limit,
                skip,
            } => (
                DbCommandRequest::IteratorKey {
                    start_key_bound,
                    order: idb_cursor_direction_to_ckb(order),
                    limit,
                    skip,
                },
                Some(take_while),
                Some(filter_map),
            ),
        };
        debug!("Dispatching database command: {:?}", new_cmd);
        let CommunicationChannel {
            input_i32_arr,
            input_u8_arr,
            output_i32_arr,
            output_u8_arr,
        } = self;
        output_i32_arr.set_index(0, InputCommand::Waiting as i32);
        write_command_with_payload(
            InputCommand::DbRequest as i32,
            new_cmd,
            input_i32_arr,
            input_u8_arr,
        )
        .with_context(|| anyhow!("Failed to write db command"))?;
        loop {
            Atomics::wait(output_i32_arr, 0, OutputCommand::Waiting as i32).unwrap();
            let output_cmd = OutputCommand::try_from(output_i32_arr.get_index(0)).unwrap();
            output_i32_arr.set_index(0, OutputCommand::Waiting as i32);
            log::trace!("Received output command: {:?}", output_cmd);
            match output_cmd {
                s @ (OutputCommand::OpenDatabaseResponse | OutputCommand::Waiting) => {
                    log::warn!("Unreachable at light-client-lib: {:?}", s);
                    continue;
                }
                OutputCommand::RequestTakeWhile => {
                    let arg = read_command_payload::<Vec<u8>>(output_i32_arr, output_u8_arr)?;
                    let ok = take_while.as_ref().unwrap()(&arg);

                    debug!(
                        "Received take while request with args {:?}, result {}",
                        arg, ok
                    );
                    write_command_with_payload(
                        InputCommand::ResponseTakeWhile as i32,
                        ok,
                        input_i32_arr,
                        input_u8_arr,
                    )?;
                    continue;
                }
                OutputCommand::RequestFilterMap => {
                    let arg = read_command_payload::<Vec<u8>>(output_i32_arr, output_u8_arr)?;
                    let result = filter_map.as_ref().unwrap()(&arg);

                    log::trace!(
                        "Received filter_map request with args {:?}, result {:?}",
                        arg,
                        result
                    );
                    write_command_with_payload(
                        InputCommand::ResponseFilterMap as i32,
                        result,
                        input_i32_arr,
                        input_u8_arr,
                    )?;
                    log::trace!("Result of RequestFilterMap written");
                    continue;
                }

                OutputCommand::DbResponse => {
                    let result =
                        read_command_payload::<DbCommandResponse>(output_i32_arr, output_u8_arr);
                    return result;
                }
                OutputCommand::Error => {
                    let payload = read_command_payload::<String>(output_i32_arr, output_u8_arr)?;
                    bail!("{}", payload);
                }
            }
        }
    }
}

static DB_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct Storage {
    channel: CommunicationChannel,
}
/// We are sure that a single light-client-wasm instance will only run on one thread.
/// So it's safe to implement [`std::marker::Send`] + [`std::marker::Sync`] for [`crate::storage::db::browser::Storage`]
unsafe impl Sync for Storage {}
unsafe impl Send for Storage {}

impl Storage {
    pub fn shutdown(&self) {
        let CommunicationChannel {
            input_i32_arr,
            input_u8_arr,
            output_i32_arr,
            ..
        } = &self.channel;
        output_i32_arr.set_index(0, InputCommand::Waiting as i32);
        write_command_with_payload(
            InputCommand::Shutdown as i32,
            (),
            input_i32_arr,
            input_u8_arr,
        )
        .unwrap();
    }
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        let chan = CommunicationChannel::prepare_from_global();
        if !DB_INITIALIZED.load(std::sync::atomic::Ordering::SeqCst) {
            chan.open_database(path.as_ref().to_str().unwrap());
            DB_INITIALIZED.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Self { channel: chan }
    }

    pub fn batch(&self) -> Batch {
        Batch {
            add: vec![],
            delete: vec![],
            comm_arrays: self.channel.clone(),
        }
    }
    pub fn put<K, V>(&self, key: K, value: V) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Put {
                kvs: vec![KV {
                    key: key.as_ref().to_vec(),
                    value: value.as_ref().to_vec(),
                }],
            })
            .map(|_| ())
            .map_err(|e| Error::Indexdb(format!("{:?}", e)))
    }
    pub fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>> {
        let values = self
            .channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Read {
                keys: vec![key.as_ref().to_vec()],
            })
            .map_err(|e| Error::Indexdb(format!("{:?}", e)))?;
        match values {
            DbCommandResponse::Read { values } => Ok(values.into_iter().last().unwrap()),
            _ => unreachable!(),
        }
    }
    #[allow(clippy::needless_lifetimes)]
    pub fn get_pinned<'a, K>(&'a self, key: K) -> Result<Option<Vec<u8>>>
    where
        K: AsRef<[u8]>,
    {
        self.get(key)
    }
    pub fn delete<K: AsRef<[u8]>>(&self, key: K) -> Result<()> {
        self.channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Delete {
                keys: vec![key.as_ref().to_vec()],
            })
            .map(|_| ())
            .map_err(|e| Error::Indexdb(format!("{:?}", e)))
    }
}

impl StorageHighLevelOperations for Storage {
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
    fn put<K, V>(&self, key: K, value: V) -> Result<()>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.put(key, value)
    }

    fn delete<K: AsRef<[u8]>>(&self, key: K) -> Result<()> {
        self.delete(key)
    }
    fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<Vec<u8>>> {
        self.get(key)
    }
    fn collect_iterator(
        &self,
        start_key_bound: Vec<u8>,
        order: GeneralDirection,
        take_while: Box<dyn Fn(&[u8]) -> bool + Send + 'static>,
        filter_map: Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static>,
        limit: usize,
        skip: usize,
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        let value = self
            .channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Iterator {
                start_key_bound,
                order: match order {
                    GeneralDirection::Forward => CursorDirection::NextUnique,
                    GeneralDirection::Reverse => CursorDirection::PrevUnique,
                },
                take_while,
                filter_map,
                limit,
                skip,
            })
            .unwrap();
        if let DbCommandResponse::Iterator { kvs } = value {
            kvs.into_iter().map(|x| (x.key, x.value)).collect()
        } else {
            unreachable!()
        }
    }
    fn is_filter_scripts_empty(&self) -> bool {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();

        let value = match self.channel.dispatch_database_command(
            CommandRequestWithTakeWhileAndFilterMap::IteratorKey {
                start_key_bound: key_prefix.clone(),
                order: CursorDirection::NextUnique,
                take_while: Box::new(move |raw_key: &[u8]| raw_key.starts_with(&key_prefix)),
                filter_map: Box::new(|s| Some(s.to_vec())),
                limit: 1,
                skip: 0,
            },
        ) {
            Ok(v) => v,
            Err(_) => return false,
        };

        if let DbCommandResponse::IteratorKey { keys } = value {
            keys.is_empty()
        } else {
            unreachable!()
        }
    }
    fn get_filter_scripts(&self) -> Vec<ScriptStatus> {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let key_prefix_clone = key_prefix.clone();
        let value = self
            .channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Iterator {
                start_key_bound: key_prefix_clone.clone(),
                order: CursorDirection::NextUnique,
                take_while: Box::new(move |raw_key: &[u8]| raw_key.starts_with(&key_prefix_clone)),
                filter_map: Box::new(|s| Some(s.to_vec())),
                limit: usize::MAX,
                skip: 0,
            })
            .unwrap();
        debug!("raw get filter script response: {:#?}", value);
        if let DbCommandResponse::Iterator { kvs } = value {
            kvs.into_iter()
                .map(|kv| (kv.key, kv.value))
                .map(|(key, value)| {
                    let script = Script::from_slice(&key[key_prefix.len()..key.len() - 1])
                        .expect("stored Script");
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
        } else {
            unreachable!()
        }
    }
    fn update_filter_scripts(&self, scripts: Vec<ScriptStatus>, command: SetScriptsCommand) {
        let mut should_filter_genesis_block = false;
        let mut batch = self.batch();
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();

        match command {
            SetScriptsCommand::All => {
                should_filter_genesis_block = scripts.iter().any(|ss| ss.block_number == 0);

                let key_prefix_clone = key_prefix.clone();
                let remove_keys = self
                    .channel
                    .dispatch_database_command(
                        CommandRequestWithTakeWhileAndFilterMap::IteratorKey {
                            start_key_bound: key_prefix_clone.clone(),
                            order: CursorDirection::NextUnique,
                            take_while: Box::new(move |raw_key: &[u8]| {
                                raw_key.starts_with(&key_prefix_clone)
                            }),
                            filter_map: Box::new(|s| Some(s.to_vec())),
                            limit: usize::MAX,
                            skip: 0,
                        },
                    )
                    .unwrap();
                debug!("Received {:?}", remove_keys);
                if let DbCommandResponse::IteratorKey { keys } = remove_keys {
                    batch.delete_many(keys).unwrap();
                } else {
                    unreachable!()
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
            .channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Iterator {
                start_key_bound: key_prefix.clone(),
                order: CursorDirection::NextUnique,
                take_while: Box::new(move |raw_key: &[u8]| raw_key.starts_with(&key_prefix)),
                filter_map: Box::new(|s| Some(s.to_vec())),
                limit: usize::MAX,
                skip: 0,
            })
            .unwrap();

        if let DbCommandResponse::Iterator { kvs } = value {
            let min_block_number = kvs
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
        } else {
            unreachable!()
        }
    }
    fn get_scripts_hash(&self, block_number: BlockNumber) -> Vec<Byte32> {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();

        let key_prefix_clone = key_prefix.clone();
        let value = self
            .channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Iterator {
                start_key_bound: key_prefix_clone.clone(),
                order: CursorDirection::NextUnique,
                take_while: Box::new(move |raw_key: &[u8]| raw_key.starts_with(&key_prefix_clone)),
                filter_map: Box::new(|s| Some(s.to_vec())),
                limit: usize::MAX,
                skip: 0,
            })
            .unwrap();

        if let DbCommandResponse::Iterator { kvs } = value {
            kvs.into_iter()
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
        } else {
            unreachable!()
        }
    }
    fn clear_matched_blocks(&self) {
        debug!(
            "Clearing matched blocks, task id {:?}",
            tokio::task::try_id()
        );
        let key_prefix: Vec<u8> = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();

        let mut batch = self.batch();

        let value = self
            .channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::IteratorKey {
                start_key_bound: key_prefix.clone(),
                order: CursorDirection::NextUnique,
                take_while: Box::new(move |raw_key: &[u8]| raw_key.starts_with(&key_prefix)),
                filter_map: Box::new(|s| Some(s.to_vec())),
                limit: usize::MAX,
                skip: 0,
            })
            .unwrap();
        if let DbCommandResponse::IteratorKey { keys } = value {
            batch.delete_many(keys).unwrap();
            batch.commit().unwrap();
        } else {
            unreachable!()
        }
    }
    fn get_matched_blocks(&self, direction: GeneralDirection) -> Option<MatchedBlocks> {
        let key_prefix = Key::Meta(MATCHED_FILTER_BLOCKS_KEY).into_vec();
        let iter_from = match direction {
            GeneralDirection::Forward => key_prefix.clone(),
            GeneralDirection::Reverse => {
                let mut key = key_prefix.clone();
                key.extend(u64::MAX.to_be_bytes());
                key
            }
        };

        let key_prefix_clone = key_prefix.clone();

        let value = self
            .channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Iterator {
                start_key_bound: iter_from,
                order: match direction {
                    GeneralDirection::Forward => CursorDirection::NextUnique,
                    GeneralDirection::Reverse => CursorDirection::PrevUnique,
                },
                take_while: Box::new(move |raw_key: &[u8]| raw_key.starts_with(&key_prefix_clone)),
                filter_map: Box::new(|s| Some(s.to_vec())),
                limit: 1,
                skip: 0,
            })
            .unwrap();
        if let DbCommandResponse::Iterator { kvs } = value {
            kvs.into_iter()
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
        } else {
            unreachable!()
        }
    }

    fn get_earliest_matched_blocks(&self) -> Option<MatchedBlocks> {
        let result = self.get_matched_blocks(GeneralDirection::Forward);
        debug!(
            "Called get earliest matched blocks: {:?}, task id {:?}",
            result,
            tokio::task::try_id()
        );
        result
    }

    fn get_latest_matched_blocks(&self) -> Option<MatchedBlocks> {
        self.get_matched_blocks(GeneralDirection::Reverse)
    }
    fn get_check_points(&self, start_index: CpIndex, limit: usize) -> Vec<Byte32> {
        let start_key = Key::CheckPointIndex(start_index).into_vec();
        let key_prefix = [KeyPrefix::CheckPointIndex as u8];

        let value = self
            .channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Iterator {
                start_key_bound: start_key,
                order: CursorDirection::NextUnique,
                take_while: Box::new(move |raw_key: &[u8]| raw_key.starts_with(&key_prefix)),
                filter_map: Box::new(|s| Some(s.to_vec())),
                limit,
                skip: 0,
            })
            .unwrap();

        if let DbCommandResponse::Iterator { kvs } = value {
            kvs.into_iter()
                .map(|kv| (kv.key, kv.value))
                .map(|(_key, value)| Byte32::from_slice(&value).expect("stored block filter hash"))
                .collect()
        } else {
            unreachable!()
        }
    }
    fn update_block_number(&self, block_number: BlockNumber) {
        let key_prefix = Key::Meta(FILTER_SCRIPTS_KEY).into_vec();
        let mut batch = self.batch();

        let value = self
            .channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Iterator {
                start_key_bound: key_prefix.clone(),
                order: CursorDirection::NextUnique,
                take_while: Box::new(move |raw_key: &[u8]| raw_key.starts_with(&key_prefix)),
                filter_map: Box::new(|s| Some(s.to_vec())),
                limit: usize::MAX,
                skip: 0,
            })
            .unwrap();

        if let DbCommandResponse::Iterator { kvs } = value {
            kvs.into_iter()
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
    }
    fn rollback_to_block(&self, to_number: BlockNumber) {
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
                    .channel
                    .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Iterator {
                        start_key_bound: start_key.clone(),
                        order: CursorDirection::PrevUnique,
                        take_while: Box::new(move |raw_key: &[u8]| {
                            raw_key.starts_with(&key_prefix)
                                && BlockNumber::from_be_bytes(
                                    raw_key[key_prefix_len..key_prefix_len + 8]
                                        .try_into()
                                        .expect("stored BlockNumber"),
                                ) >= to_number
                        }),
                        filter_map: Box::new(|s| Some(s.to_vec())),
                        limit: usize::MAX,
                        skip: 0,
                    })
                    .unwrap();

                if let DbCommandResponse::Iterator { kvs } = value {
                    for (key, value) in kvs.into_iter().map(|kv| (kv.key, kv.value)) {
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
                        let tx_hash =
                            packed::Byte32Reader::from_slice_should_be_ok(&value).to_entity();
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
                } else {
                    unreachable!()
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

pub struct Batch {
    add: Vec<KV>,
    delete: Vec<Vec<u8>>,
    comm_arrays: CommunicationChannel,
}

impl Batch {
    pub fn put_kv<K: Into<Vec<u8>>, V: Into<Vec<u8>>>(&mut self, key: K, value: V) -> Result<()> {
        self.add.push(KV {
            key: key.into(),
            value: value.into(),
        });
        Ok(())
    }

    pub fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(&mut self, key: K, value: V) -> Result<()> {
        self.add.push(KV {
            key: key.as_ref().to_vec(),
            value: value.as_ref().to_vec(),
        });
        Ok(())
    }

    pub fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<()> {
        self.delete.push(key.as_ref().to_vec());
        Ok(())
    }

    pub fn delete_many(&mut self, keys: Vec<Vec<u8>>) -> Result<()> {
        self.comm_arrays
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Delete { keys })
            .map(|_| ())
            .map_err(|e| Error::Indexdb(format!("{:?}", e)))
    }

    pub fn commit(self) -> Result<()> {
        if !self.add.is_empty() {
            self.comm_arrays
                .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Put {
                    kvs: self.add,
                })
                .map(|_| ())
                .map_err(|e| Error::Indexdb(format!("{:?}", e)))?;
        }

        if !self.delete.is_empty() {
            self.comm_arrays
                .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Delete {
                    keys: self.delete,
                })
                .map(|_| ())
                .map_err(|e| Error::Indexdb(format!("{:?}", e)))?;
        }

        Ok(())
    }
}
