use std::{cell::RefCell, path::Path, sync::atomic::AtomicBool};

use super::super::backend::{BatchWriter, FilterMapFn, StorageBackend, TakeWhileFn};
use super::super::storage_trait::LightClientStorage;
use super::super::{Byte32, Key};
use super::iterator::KVPair;
use anyhow::{anyhow, bail, Context};

use ckb_types::{
    core::{
        cell::{CellMeta, CellStatus},
        HeaderView, TransactionInfo,
    },
    packed::{CellOutput, Header, OutPoint},
    prelude::*,
};
use light_client_db_common::{
    read_command_payload, write_command_with_payload, DbCommandRequest, DbCommandResponse,
    InputCommand, IteratorDirection, OutputCommand, KV,
};

use log::debug;

use crate::error::{Error, Result};
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue};
use web_sys::js_sys::{Atomics, Int32Array, SharedArrayBuffer, Uint8Array};

// Enum to handle different filter_map signatures
#[allow(clippy::type_complexity)]
#[allow(dead_code)]
enum FilterMapType {
    Single(Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static>),
    Pair(Box<dyn Fn(&[u8], &[u8]) -> Option<Vec<u8>> + Send + 'static>),
}

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
        direction: IteratorDirection,
        take_while: Box<dyn Fn(&[u8]) -> bool + Send + 'static>,
        filter_map: Box<dyn Fn(&[u8], &[u8]) -> Option<Vec<u8>> + Send + 'static>,
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
    #[allow(clippy::type_complexity)]
    fn dispatch_database_command(
        &self,
        cmd: CommandRequestWithTakeWhileAndFilterMap,
    ) -> anyhow::Result<DbCommandResponse> {
        let (new_cmd, take_while, filter_map): (
            DbCommandRequest,
            Option<Box<dyn Fn(&[u8]) -> bool + Send + 'static>>,
            Option<FilterMapType>,
        ) = match cmd {
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
                direction,
                take_while,
                filter_map,
                limit,
                skip,
            } => (
                DbCommandRequest::Iterator {
                    start_key_bound,
                    direction,
                    limit,
                    skip,
                },
                Some(take_while),
                Some(FilterMapType::Pair(filter_map)),
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
                    // Handle both single-arg and two-arg filter_map
                    let result = match filter_map.as_ref().unwrap() {
                        FilterMapType::Single(f) => {
                            // IteratorKey case: read just the key
                            let arg =
                                read_command_payload::<Vec<u8>>(output_i32_arr, output_u8_arr)?;
                            f(&arg)
                        }
                        FilterMapType::Pair(f) => {
                            // Iterator case: read (key, value) tuple
                            let (key, value) = read_command_payload::<(Vec<u8>, Vec<u8>)>(
                                output_i32_arr,
                                output_u8_arr,
                            )?;
                            f(&key, &value)
                        }
                    };

                    log::trace!("Received filter_map request, result {:?}", result);
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

    #[allow(clippy::type_complexity)]
    fn collect_iterator(
        &self,
        start_key_bound: Vec<u8>,
        direction: IteratorDirection,
        take_while: Box<dyn Fn(&[u8]) -> bool + Send + 'static>,
        filter_map: Box<dyn Fn(&[u8], &[u8]) -> Option<Vec<u8>> + Send + 'static>,
        limit: usize,
        skip: usize,
    ) -> Vec<KV> {
        let value = self
            .channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Iterator {
                start_key_bound,
                direction,
                take_while,
                filter_map,
                limit,
                skip,
            })
            .unwrap();
        if let DbCommandResponse::Iterator { kvs } = value {
            kvs
        } else {
            unreachable!()
        }
    }

    pub fn cell(&self, out_point: &OutPoint, _eager_load: bool) -> CellStatus {
        if let Some((block_number, tx_index, tx)) = self.get_transaction(&out_point.tx_hash()) {
            let block_hash = Byte32::from_slice(
                &StorageBackend::get(self, Key::BlockNumber(block_number).into_vec())
                    .expect("db get should be ok")
                    .expect("stored block number / hash mapping"),
            )
            .expect("stored block hash should be OK");

            let header = Header::from_slice(
                &StorageBackend::get(self, Key::BlockHash(&block_hash).into_vec())
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

    pub fn get_header(&self, hash: &Byte32) -> Option<HeaderView> {
        LightClientStorage::get_header(self, hash)
    }
}

pub struct Batch {
    add: Vec<KV>,
    delete: Vec<Vec<u8>>,
    comm_arrays: CommunicationChannel,
}

// Implement BatchWriter trait for Batch
impl BatchWriter for Batch {
    fn put(&mut self, key: &[u8], value: &[u8]) {
        self.add.push(KV {
            key: key.to_vec(),
            value: value.to_vec(),
        });
    }

    fn delete(&mut self, key: &[u8]) {
        self.delete.push(key.to_vec());
    }

    fn commit(self) -> Result<()> {
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

// Implementation of StorageBackend trait for IndexedDB
impl StorageBackend for Storage {
    type Batch = Batch;

    fn get(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>> {
        let values = self
            .channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Read {
                keys: vec![key],
            })
            .map_err(|e| Error::Indexdb(format!("{:?}", e)))?;
        match values {
            DbCommandResponse::Read { values } => Ok(values.into_iter().last().unwrap()),
            _ => unreachable!(),
        }
    }

    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        self.channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Put {
                kvs: vec![KV { key, value }],
            })
            .map(|_| ())
            .map_err(|e| Error::Indexdb(format!("{:?}", e)))
    }

    fn delete(&self, key: &[u8]) -> Result<()> {
        self.channel
            .dispatch_database_command(CommandRequestWithTakeWhileAndFilterMap::Delete {
                keys: vec![key.to_vec()],
            })
            .map(|_| ())
            .map_err(|e| Error::Indexdb(format!("{:?}", e)))
    }

    fn batch(&self) -> Self::Batch {
        Batch {
            add: vec![],
            delete: vec![],
            comm_arrays: self.channel.clone(),
        }
    }

    fn collect_iterator(
        &self,
        from_key: Vec<u8>,
        direction: super::iterator::IteratorDirection,
        take_while_fn: TakeWhileFn,
        filter_map_fn: FilterMapFn,
        skip: usize,
        limit: usize,
    ) -> Vec<KVPair> {
        // Convert local IteratorDirection to db-common IteratorDirection
        let db_direction = match direction {
            super::iterator::IteratorDirection::Forward => IteratorDirection::Forward,
            super::iterator::IteratorDirection::Reverse => IteratorDirection::Reverse,
        };

        // Use the browser storage's collect_iterator which now provides both key and value to filter_map
        let kvs = Storage::collect_iterator(
            self,
            from_key,
            db_direction,
            take_while_fn,
            filter_map_fn,
            limit,
            skip,
        );

        // Convert KV to KVPair
        kvs.into_iter()
            .map(|kv| KVPair {
                key: kv.key,
                value: kv.value,
            })
            .collect()
    }
}

// Implementation of LightClientStorage trait for IndexedDB
// All methods use default implementations from the trait
impl LightClientStorage for Storage {}
