use std::sync::Arc;

use ckb_chain_spec::consensus::Consensus;
use ckb_jsonrpc_types::{
    BlockView, EstimateCycles, HeaderView, JsonBytes, NodeAddress, RemoteNodeProtocol, Transaction,
    Uint32,
};
use ckb_light_client_lib::error::{Error, Result};
use ckb_light_client_lib::protocols::Peers;
use ckb_light_client_lib::service::{
    Cell, CellType, CellsCapacity, FetchStatus, LocalNode, LocalNodeProtocol, Order, Pagination,
    PeerSyncState, RemoteNode, ScriptStatus, ScriptType, SearchKey, SetScriptsCommand, Status,
    TransactionWithStatus, Tx, TxStatus, TxWithCell, TxWithCells,
};
use ckb_light_client_lib::storage::db::{
    GeneralDirection, StorageGeneralOperations, StorageGetPinnedRelatedOperations,
    StorageHighLevelOperations,
};
use ckb_light_client_lib::storage::extract_raw_data;
use ckb_light_client_lib::storage::{self, Key, KeyPrefix, LAST_STATE_KEY, StorageWithChainData};
use ckb_light_client_lib::verify::verify_tx;
use ckb_network::{NetworkController, extract_peer_id};
use ckb_systemtime::unix_time_as_millis;
use ckb_traits::CellDataProvider;
use ckb_traits::HeaderProvider;
use ckb_types::prelude::IntoTransactionView;
use ckb_types::prelude::Reader;
use ckb_types::prelude::{
    Entity, FromSliceShouldBeOk, IntoBlockView, IntoHeaderView, Pack, Unpack,
};
use ckb_types::{H256, packed};
pub trait BlockFilterRpcMethods {
    fn set_scripts(
        &self,
        scripts: Vec<ScriptStatus>,
        command: Option<SetScriptsCommand>,
    ) -> Result<()>;

    fn get_scripts(&self) -> Result<Vec<ScriptStatus>>;

    fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>>;

    fn get_transactions(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after: Option<JsonBytes>,
    ) -> Result<Pagination<Tx>>;

    fn get_cells_capacity(&self, search_key: SearchKey) -> Result<CellsCapacity>;
}

pub trait TransactionRpcMethods {
    fn send_transaction(&self, tx: Transaction) -> Result<H256>;
    fn get_transaction(&self, tx_hash: H256) -> Result<TransactionWithStatus>;
    fn fetch_transaction(&self, tx_hash: H256) -> Result<FetchStatus<TransactionWithStatus>>;
}

pub trait ChainRpcMethods {
    fn get_tip_header(&self) -> Result<HeaderView>;
    fn get_genesis_block(&self) -> Result<BlockView>;
    fn get_header(&self, block_hash: H256) -> Result<Option<HeaderView>>;
    fn fetch_header(
        &self,
        block_hash: H256,
    ) -> Result<ckb_light_client_lib::service::FetchStatus<HeaderView>>;
    fn estimate_cycles(&self, tx: Transaction) -> Result<EstimateCycles>;
}

pub trait NetRpcMethods {
    fn local_node_info(&self) -> Result<LocalNode>;
    fn get_peers(&self) -> Result<Vec<RemoteNode>>;
}

pub struct BlockFilterRpcImpl<S: StorageHighLevelOperations + Send + Sync + Clone + 'static> {
    pub swc: StorageWithChainData<S>,
}

pub struct TransactionRpcImpl<
    S: StorageHighLevelOperations
        + StorageGetPinnedRelatedOperations
        + CellDataProvider
        + Send
        + Sync
        + Clone
        + 'static,
> {
    pub swc: StorageWithChainData<S>,
    pub consensus: Arc<Consensus>,
}

pub struct ChainRpcImpl<
    S: StorageHighLevelOperations
        + StorageGeneralOperations
        + StorageGetPinnedRelatedOperations
        + CellDataProvider
        + Send
        + Sync
        + Clone
        + 'static,
> {
    pub swc: StorageWithChainData<S>,
    pub consensus: Arc<Consensus>,
}

pub struct NetRpcImpl {
    pub network_controller: NetworkController,
    pub peers: Arc<Peers>,
}

const MAX_ADDRS: usize = 50;

impl NetRpcMethods for NetRpcImpl {
    fn local_node_info(&self) -> Result<LocalNode> {
        Ok(LocalNode {
            version: self.network_controller.version().to_owned(),
            node_id: self.network_controller.node_id(),
            active: self.network_controller.is_active(),
            addresses: self
                .network_controller
                .public_urls(MAX_ADDRS)
                .into_iter()
                .map(|(address, score)| NodeAddress {
                    address,
                    score: u64::from(score).into(),
                })
                .collect(),
            protocols: self
                .network_controller
                .protocols()
                .into_iter()
                .map(|(protocol_id, name, support_versions)| LocalNodeProtocol {
                    id: (protocol_id.value() as u64).into(),
                    name,
                    support_versions,
                })
                .collect::<Vec<_>>(),
            connections: (self.network_controller.connected_peers().len() as u64).into(),
        })
    }

    fn get_peers(&self) -> Result<Vec<RemoteNode>> {
        let peers: Vec<RemoteNode> = self
            .network_controller
            .connected_peers()
            .iter()
            .map(|(peer_index, peer)| {
                let mut addresses = vec![&peer.connected_addr];
                addresses.extend(peer.listened_addrs.iter());

                let node_addresses = addresses
                    .iter()
                    .map(|addr| {
                        let score = self
                            .network_controller
                            .addr_info(addr)
                            .map(|addr_info| addr_info.score)
                            .unwrap_or(1);
                        let non_negative_score = if score > 0 { score as u64 } else { 0 };
                        NodeAddress {
                            address: addr.to_string(),
                            score: non_negative_score.into(),
                        }
                    })
                    .collect();

                RemoteNode {
                    version: peer
                        .identify_info
                        .as_ref()
                        .map(|info| info.client_version.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    node_id: extract_peer_id(&peer.connected_addr)
                        .map(|peer_id| peer_id.to_base58())
                        .unwrap_or_default(),
                    addresses: node_addresses,
                    connected_duration: (ckb_light_client_lib::types::Instant::now()
                        .saturating_duration_since(peer.connected_time)
                        .as_millis() as u64)
                        .into(),
                    sync_state: self.peers.get_state(peer_index).map(|state| PeerSyncState {
                        requested_best_known_header: state
                            .get_prove_request()
                            .map(|request| request.get_last_header().header().to_owned().into()),
                        proved_best_known_header: state
                            .get_prove_state()
                            .map(|request| request.get_last_header().header().to_owned().into()),
                    }),
                    protocols: peer
                        .protocols
                        .iter()
                        .map(|(protocol_id, protocol_version)| RemoteNodeProtocol {
                            id: (protocol_id.value() as u64).into(),
                            version: protocol_version.clone(),
                        })
                        .collect(),
                }
            })
            .collect();
        Ok(peers)
    }
}

impl<
    S: StorageHighLevelOperations
        + StorageGetPinnedRelatedOperations
        + CellDataProvider
        + Send
        + Sync
        + Clone
        + 'static,
> TransactionRpcMethods for TransactionRpcImpl<S>
{
    fn send_transaction(&self, tx: Transaction) -> Result<H256> {
        let tx: packed::Transaction = tx.into();
        let tx = tx.into_view();
        let cycles = verify_tx(
            tx.clone(),
            &self.swc,
            Arc::clone(&self.consensus),
            &self.swc.storage().get_last_state().1.into_view(),
        )
        .map_err(|e| Error::runtime(format!("invalid transaction: {:?}", e)))?;
        #[cfg(target_arch = "wasm32")]
        self.swc
            .pending_txs()
            .blocking_write()
            .push(tx.clone(), cycles);

        #[cfg(not(target_arch = "wasm32"))]
        self.swc
            .pending_txs()
            .write()
            .expect("pending_txs lock is poisoned")
            .push(tx.clone(), cycles);

        Ok(tx.hash().unpack())
    }

    fn get_transaction(&self, tx_hash: H256) -> Result<TransactionWithStatus> {
        if let Some((transaction, header)) = self
            .swc
            .storage()
            .get_transaction_with_header(&tx_hash.pack())
        {
            return Ok(TransactionWithStatus {
                transaction: Some(transaction.into_view().into()),
                cycles: None,
                tx_status: TxStatus {
                    block_hash: Some(header.into_view().hash().unpack()),
                    status: Status::Committed,
                },
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        let pending_tx = self
            .swc
            .pending_txs()
            .read()
            .expect("pending_txs lock is poisoned")
            .get(&tx_hash.pack());
        #[cfg(target_arch = "wasm32")]
        let pending_tx = self.swc.pending_txs().blocking_read().get(&tx_hash.pack());
        if let Some((transaction, cycles, _)) = pending_tx {
            return Ok(TransactionWithStatus {
                transaction: Some(transaction.into_view().into()),
                cycles: Some(cycles.into()),
                tx_status: TxStatus {
                    block_hash: None,
                    status: Status::Pending,
                },
            });
        }

        Ok(TransactionWithStatus {
            transaction: None,
            cycles: None,
            tx_status: TxStatus {
                block_hash: None,
                status: Status::Unknown,
            },
        })
    }

    fn fetch_transaction(&self, tx_hash: H256) -> Result<FetchStatus<TransactionWithStatus>> {
        let tws = self.get_transaction(tx_hash.clone())?;
        if tws.transaction.is_some() {
            return Ok(FetchStatus::Fetched { data: tws });
        }

        let now = unix_time_as_millis();
        if let Some((added_ts, first_sent, missing)) = self.swc.get_tx_fetch_info(&tx_hash) {
            if missing {
                // re-fetch the transaction
                self.swc.add_fetch_tx(tx_hash, now);
                return Ok(FetchStatus::NotFound);
            } else if first_sent > 0 {
                return Ok(FetchStatus::Fetching {
                    first_sent: first_sent.into(),
                });
            } else {
                return Ok(FetchStatus::Added {
                    timestamp: added_ts.into(),
                });
            }
        } else {
            self.swc.add_fetch_tx(tx_hash, now);
        }
        Ok(FetchStatus::Added {
            timestamp: now.into(),
        })
    }
}

impl<
    S: StorageHighLevelOperations
        + StorageGeneralOperations
        + StorageGetPinnedRelatedOperations
        + CellDataProvider
        + Send
        + Sync
        + Clone
        + 'static,
> ChainRpcMethods for ChainRpcImpl<S>
{
    fn get_tip_header(&self) -> Result<HeaderView> {
        Ok(self.swc.storage().get_tip_header().into_view().into())
    }

    fn get_genesis_block(&self) -> Result<BlockView> {
        Ok(self.swc.storage().get_genesis_block().into_view().into())
    }

    fn get_header(&self, block_hash: H256) -> Result<Option<HeaderView>> {
        Ok(self.swc.get_header(&block_hash.pack()).map(Into::into))
    }

    fn fetch_header(&self, block_hash: H256) -> Result<FetchStatus<HeaderView>> {
        if let Some(value) = self.swc.storage().get_header(&block_hash.pack()) {
            return Ok(FetchStatus::Fetched { data: value.into() });
        }
        let now = unix_time_as_millis();
        if let Some((added_ts, first_sent, missing)) = self.swc.get_header_fetch_info(&block_hash) {
            if missing {
                // re-fetch the header
                self.swc.add_fetch_header(block_hash, now);
                return Ok(FetchStatus::NotFound);
            } else if first_sent > 0 {
                return Ok(FetchStatus::Fetching {
                    first_sent: first_sent.into(),
                });
            } else {
                return Ok(FetchStatus::Added {
                    timestamp: added_ts.into(),
                });
            }
        } else {
            self.swc.add_fetch_header(block_hash, now);
        }
        Ok(FetchStatus::Added {
            timestamp: now.into(),
        })
    }

    fn estimate_cycles(&self, tx: Transaction) -> Result<EstimateCycles> {
        let tx: packed::Transaction = tx.into();
        let tx = tx.into_view();
        let cycles = verify_tx(
            tx.clone(),
            &self.swc,
            Arc::clone(&self.consensus),
            &self.swc.storage().get_last_state().1.into_view(),
        )
        .map_err(|e| Error::runtime(format!("invalid transaction: {:?}", e)))?;
        Ok(EstimateCycles {
            cycles: cycles.into(),
        })
    }
}

impl<S: StorageHighLevelOperations + Send + Sync + Clone + 'static> BlockFilterRpcMethods
    for BlockFilterRpcImpl<S>
{
    #[cfg(not(target_arch = "wasm32"))]
    fn set_scripts(
        &self,
        scripts: Vec<ScriptStatus>,
        command: Option<SetScriptsCommand>,
    ) -> Result<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        let swc = self.swc.clone();
        std::thread::spawn(move || {
            let mut matched_blocks = swc.matched_blocks().blocking_write();
            let scripts = scripts.into_iter().map(Into::into).collect();
            swc.storage()
                .update_filter_scripts(scripts, command.map(Into::into).unwrap_or_default());
            matched_blocks.clear();
            tx.send(()).unwrap();
        });
        rx.recv().unwrap();
        Ok(())
    }
    #[cfg(target_arch = "wasm32")]
    fn set_scripts(
        &self,
        scripts: Vec<ScriptStatus>,
        command: Option<SetScriptsCommand>,
    ) -> Result<()> {
        let mut matched_blocks = self.swc.matched_blocks().blocking_write();
        self.swc.storage().update_filter_scripts(
            scripts.into_iter().map(Into::into).collect(),
            command.map(Into::into).unwrap_or_default(),
        );
        matched_blocks.clear();
        Ok(())
    }

    fn get_scripts(&self) -> Result<Vec<ScriptStatus>> {
        let scripts = self.swc.storage().get_filter_scripts();
        Ok(scripts.into_iter().map(Into::into).collect())
    }

    fn get_cells(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after_cursor: Option<JsonBytes>,
    ) -> Result<Pagination<Cell>> {
        let (prefix, from_key, direction, skip) = build_query_options(
            &search_key,
            KeyPrefix::CellLockScript,
            KeyPrefix::CellTypeScript,
            order,
            after_cursor,
        )?;

        let limit = limit.value() as usize;
        if limit == 0 {
            return Err(Error::runtime("limit should be greater than 0"));
        }
        let with_data = search_key.with_data.unwrap_or(true);
        let filter_script_type = match search_key.script_type {
            ScriptType::Lock => ScriptType::Type,
            ScriptType::Type => ScriptType::Lock,
        };

        let (
            filter_prefix,
            filter_script_len_range,
            filter_output_data_len_range,
            filter_output_capacity_range,
            filter_block_range,
        ) = build_filter_options(search_key)?;

        fn extract_data_from_key(key: &[u8]) -> (u32, u32, u64) {
            let output_index = u32::from_be_bytes(
                key[key.len() - 4..]
                    .try_into()
                    .expect("stored output_index"),
            );
            let tx_index = u32::from_be_bytes(
                key[key.len() - 8..key.len() - 4]
                    .try_into()
                    .expect("stored tx_index"),
            );
            let block_number = u64::from_be_bytes(
                key[key.len() - 16..key.len() - 8]
                    .try_into()
                    .expect("stored block_number"),
            );
            (output_index, tx_index, block_number)
        }

        let storage = self.swc.storage();
        let storage_cloned = storage.clone();
        let kvs: Vec<_> = storage.collect_iterator(
            from_key.clone(),
            direction,
            Box::new(move |key| key.starts_with(&prefix)),
            Box::new(move |key| {
                let value = storage_cloned.get(key).unwrap().unwrap();
                let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
                trace!("get cells iterator at {:?} {:?}", key, value);
                let (output_index, _tx_index, block_number) = extract_data_from_key(key);
                let tx_data = &storage_cloned
                    .get(Key::TxHash(&tx_hash).into_vec())
                    .unwrap()
                    .expect("stored tx")[12..];
                trace!("tx hash = {:?}, tx data = {:?}", tx_hash, tx_data);
                let tx = packed::Transaction::from_slice(tx_data)
                    .expect("from stored tx slice should be OK");
                let output = tx
                    .raw()
                    .outputs()
                    .get(output_index as usize)
                    .expect("get output by index should be OK");
                let output_data = tx
                    .raw()
                    .outputs_data()
                    .get(output_index as usize)
                    .expect("get output data by index should be OK");

                if let Some(prefix) = filter_prefix.as_ref() {
                    match filter_script_type {
                        ScriptType::Lock => {
                            if !extract_raw_data(&output.lock())
                                .as_slice()
                                .starts_with(prefix)
                            {
                                trace!("skipped at {}", line!());
                                return None;
                            }
                        }
                        ScriptType::Type => {
                            if output.type_().is_none()
                                || !extract_raw_data(&output.type_().to_opt().unwrap())
                                    .as_slice()
                                    .starts_with(prefix)
                            {
                                trace!("skipped at {}", line!());
                                return None;
                            }
                        }
                    }
                }

                if let Some([r0, r1]) = filter_script_len_range {
                    match filter_script_type {
                        ScriptType::Lock => {
                            let script_len = extract_raw_data(&output.lock()).len();
                            if script_len < r0 || script_len > r1 {
                                trace!("skipped at {}", line!());
                                return None;
                            }
                        }
                        ScriptType::Type => {
                            let script_len = output
                                .type_()
                                .to_opt()
                                .map(|script| extract_raw_data(&script).len())
                                .unwrap_or_default();
                            if script_len < r0 || script_len > r1 {
                                trace!("skipped at {}", line!());
                                return None;
                            }
                        }
                    }
                }

                if let Some([r0, r1]) = filter_output_data_len_range
                    && (output_data.len() < r0 || output_data.len() >= r1)
                {
                    trace!("skipped at {}", line!());
                    return None;
                }

                if let Some([r0, r1]) = filter_output_capacity_range {
                    let capacity: core::Capacity = output.capacity().unpack();
                    if capacity < r0 || capacity >= r1 {
                        trace!("skipped at {}", line!());
                        return None;
                    }
                }

                if let Some([r0, r1]) = filter_block_range
                    && (block_number < r0 || block_number >= r1)
                {
                    trace!("skipped at {}", line!());
                    return None;
                }
                Some(key.to_vec())
            }),
            limit,
            skip,
        );
        trace!("get_cells: collect_iterator done");
        let mut cells = Vec::new();
        let mut last_key = Vec::new();
        for (key, value) in kvs.into_iter() {
            let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
            let (output_index, tx_index, block_number) = extract_data_from_key(&key);
            let tx = packed::Transaction::from_slice(
                &storage
                    .get(Key::TxHash(&tx_hash).into_vec())
                    .unwrap()
                    .expect("stored tx")[12..],
            )
            .expect("from stored tx slice should be OK");
            let output = tx
                .raw()
                .outputs()
                .get(output_index as usize)
                .expect("get output by index should be OK");
            let output_data = tx
                .raw()
                .outputs_data()
                .get(output_index as usize)
                .expect("get output data by index should be OK");

            last_key = key.to_vec();
            let cell_to_push = Cell {
                output: output.into(),
                output_data: if with_data {
                    Some(output_data.into())
                } else {
                    None
                },
                out_point: packed::OutPoint::new(tx_hash, output_index).into(),
                block_number: block_number.into(),
                tx_index: tx_index.into(),
            };
            cells.push(cell_to_push);
            if cells.len() >= limit {
                break;
            }
        }

        trace!("get_cells last_key={:?}", last_key);
        Ok(Pagination {
            objects: cells,
            last_cursor: JsonBytes::from_vec(last_key),
        })
    }

    fn get_transactions(
        &self,
        search_key: SearchKey,
        order: Order,
        limit: Uint32,
        after_cursor: Option<JsonBytes>,
    ) -> Result<Pagination<Tx>> {
        let (prefix, from_key, direction, skip) = build_query_options(
            &search_key,
            KeyPrefix::TxLockScript,
            KeyPrefix::TxTypeScript,
            order,
            after_cursor,
        )?;

        let limit = limit.value() as usize;
        if limit == 0 {
            return Err(Error::runtime("limit should be greater than 0"));
        }

        let filter_script_type = match search_key.script_type {
            ScriptType::Lock => ScriptType::Type,
            ScriptType::Type => ScriptType::Lock,
        };

        let (filter_script, filter_block_range) = if let Some(filter) = search_key.filter.as_ref() {
            if filter.output_data_len_range.is_some() {
                return Err(Error::runtime(
                    "doesn't support search_key.filter.output_data_len_range parameter",
                ));
            }
            if filter.output_capacity_range.is_some() {
                return Err(Error::runtime(
                    "doesn't support search_key.filter.output_capacity_range parameter",
                ));
            }
            let filter_script: Option<packed::Script> =
                filter.script.as_ref().map(|script| script.clone().into());
            let filter_block_range: Option<[core::BlockNumber; 2]> =
                filter.block_range.map(|r| [r[0].into(), r[1].into()]);
            (filter_script, filter_block_range)
        } else {
            (None, None)
        };

        let storage = self.swc.storage();

        if search_key.group_by_transaction.unwrap_or_default() {
            let prefix_cloned = prefix.clone();
            let mut kvs: Vec<_> = storage.collect_iterator(
                from_key,
                direction,
                Box::new(move |key| key.starts_with(&prefix_cloned)),
                Box::new(move |key| Some(key.to_vec())),
                100,
                skip,
            );
            let mut tx_with_cells: Vec<TxWithCells> = Vec::new();
            let mut last_key = Vec::new();

            'outer: while !kvs.is_empty() {
                for (key, value) in kvs.into_iter() {
                    let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
                    if tx_with_cells.len() == limit
                        && tx_with_cells.last_mut().unwrap().transaction.hash != tx_hash.unpack()
                    {
                        break 'outer;
                    }
                    last_key = key.to_vec();
                    let tx = packed::Transaction::from_slice(
                        &storage
                            .get(Key::TxHash(&tx_hash).into_vec())
                            .expect("get tx should be OK")
                            .expect("stored tx")[12..],
                    )
                    .expect("from stored tx slice should be OK");

                    let block_number = u64::from_be_bytes(
                        key[key.len() - 17..key.len() - 9]
                            .try_into()
                            .expect("stored block_number"),
                    );
                    let tx_index = u32::from_be_bytes(
                        key[key.len() - 9..key.len() - 5]
                            .try_into()
                            .expect("stored tx_index"),
                    );
                    let io_index = u32::from_be_bytes(
                        key[key.len() - 5..key.len() - 1]
                            .try_into()
                            .expect("stored io_index"),
                    );
                    let io_type = if *key.last().expect("stored io_type") == 0 {
                        CellType::Input
                    } else {
                        CellType::Output
                    };

                    if let Some(filter_script) = filter_script.as_ref() {
                        let filter_script_matched = match filter_script_type {
                            ScriptType::Lock => storage
                                .get(
                                    Key::TxLockScript(
                                        filter_script,
                                        block_number,
                                        tx_index,
                                        io_index,
                                        match io_type {
                                            CellType::Input => storage::CellType::Input,
                                            CellType::Output => storage::CellType::Output,
                                        },
                                    )
                                    .into_vec(),
                                )
                                .expect("get TxLockScript should be OK")
                                .is_some(),
                            ScriptType::Type => storage
                                .get(
                                    Key::TxTypeScript(
                                        filter_script,
                                        block_number,
                                        tx_index,
                                        io_index,
                                        match io_type {
                                            CellType::Input => storage::CellType::Input,
                                            CellType::Output => storage::CellType::Output,
                                        },
                                    )
                                    .into_vec(),
                                )
                                .expect("get TxTypeScript should be OK")
                                .is_some(),
                        };

                        if !filter_script_matched {
                            continue;
                        }
                    }

                    if let Some([r0, r1]) = filter_block_range
                        && (block_number < r0 || block_number >= r1)
                    {
                        continue;
                    }

                    let last_tx_hash_is_same = tx_with_cells
                        .last_mut()
                        .map(|last| {
                            if last.transaction.hash == tx_hash.unpack() {
                                last.cells.push((io_type.clone(), io_index.into()));
                                true
                            } else {
                                false
                            }
                        })
                        .unwrap_or_default();

                    if !last_tx_hash_is_same {
                        tx_with_cells.push(TxWithCells {
                            transaction: tx.into_view().into(),
                            block_number: block_number.into(),
                            tx_index: tx_index.into(),
                            cells: vec![(io_type, io_index.into())],
                        });
                    }
                }
                let prefix_cloned = prefix.clone();
                kvs = storage.collect_iterator(
                    last_key.clone(),
                    direction,
                    Box::new(move |key| key.starts_with(&prefix_cloned)),
                    Box::new(|k| Some(k.to_vec())),
                    100,
                    1,
                );
            }
            Ok(Pagination {
                objects: tx_with_cells.into_iter().map(Tx::Grouped).collect(),
                last_cursor: JsonBytes::from_vec(last_key),
            })
        } else {
            let storage_cloned = storage.clone();
            let kvs: Vec<_> = storage.collect_iterator(
                from_key.clone(),
                direction,
                Box::new(move |key| key.starts_with(&prefix)),
                Box::new(move |key| {
                    let block_number = u64::from_be_bytes(
                        key[key.len() - 17..key.len() - 9]
                            .try_into()
                            .expect("stored block_number"),
                    );
                    let tx_index = u32::from_be_bytes(
                        key[key.len() - 9..key.len() - 5]
                            .try_into()
                            .expect("stored tx_index"),
                    );
                    let io_index = u32::from_be_bytes(
                        key[key.len() - 5..key.len() - 1]
                            .try_into()
                            .expect("stored io_index"),
                    );
                    let io_type = if *key.last().expect("stored io_type") == 0 {
                        CellType::Input
                    } else {
                        CellType::Output
                    };

                    if let Some(filter_script) = filter_script.as_ref() {
                        match filter_script_type {
                            ScriptType::Lock => {
                                storage_cloned
                                    .get(
                                        Key::TxLockScript(
                                            filter_script,
                                            block_number,
                                            tx_index,
                                            io_index,
                                            match io_type {
                                                CellType::Input => storage::CellType::Input,
                                                CellType::Output => storage::CellType::Output,
                                            },
                                        )
                                        .into_vec(),
                                    )
                                    .expect("get TxLockScript should be OK")?;
                            }
                            ScriptType::Type => {
                                storage_cloned
                                    .get(
                                        Key::TxTypeScript(
                                            filter_script,
                                            block_number,
                                            tx_index,
                                            io_index,
                                            match io_type {
                                                CellType::Input => storage::CellType::Input,
                                                CellType::Output => storage::CellType::Output,
                                            },
                                        )
                                        .into_vec(),
                                    )
                                    .expect("get TxTypeScript should be OK")?;
                            }
                        }
                    }

                    if let Some([r0, r1]) = filter_block_range
                        && (block_number < r0 || block_number >= r1)
                    {
                        return None;
                    }

                    Some(key.to_vec())
                }),
                limit,
                skip,
            );

            let mut last_key = Vec::new();
            let mut txs = Vec::new();

            for (key, value) in kvs.into_iter() {
                let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
                let tx = packed::Transaction::from_slice(
                    &storage
                        .get(Key::TxHash(&tx_hash).into_vec())
                        .expect("get tx should be OK")
                        .expect("stored tx")[12..],
                )
                .expect("from stored tx slice should be OK");

                let block_number = u64::from_be_bytes(
                    key[key.len() - 17..key.len() - 9]
                        .try_into()
                        .expect("stored block_number"),
                );
                let tx_index = u32::from_be_bytes(
                    key[key.len() - 9..key.len() - 5]
                        .try_into()
                        .expect("stored tx_index"),
                );
                let io_index = u32::from_be_bytes(
                    key[key.len() - 5..key.len() - 1]
                        .try_into()
                        .expect("stored io_index"),
                );
                let io_type = if *key.last().expect("stored io_type") == 0 {
                    CellType::Input
                } else {
                    CellType::Output
                };

                last_key = key.to_vec();
                let tx_to_push = Tx::Ungrouped(TxWithCell {
                    transaction: tx.into_view().into(),
                    block_number: block_number.into(),
                    tx_index: tx_index.into(),
                    io_index: io_index.into(),
                    io_type,
                });
                txs.push(tx_to_push);
                if txs.len() >= limit {
                    break;
                }
            }

            Ok(Pagination {
                objects: txs,
                last_cursor: JsonBytes::from_vec(last_key),
            })
        }
    }

    fn get_cells_capacity(&self, search_key: SearchKey) -> Result<CellsCapacity> {
        let (prefix, from_key, direction, skip) = build_query_options(
            &search_key,
            KeyPrefix::CellLockScript,
            KeyPrefix::CellTypeScript,
            Order::Asc,
            None,
        )?;
        let filter_script_type = match search_key.script_type {
            ScriptType::Lock => ScriptType::Type,
            ScriptType::Type => ScriptType::Lock,
        };
        let (
            filter_prefix,
            filter_script_len_range,
            filter_output_data_len_range,
            filter_output_capacity_range,
            filter_block_range,
        ) = build_filter_options(search_key)?;

        let storage = self.swc.storage();
        let storage_cloned = storage.clone();

        log::trace!("get_cells_capacity: before entering collect iterator");

        let kvs: Vec<_> = storage.collect_iterator(
            from_key,
            direction,
            Box::new(move |key| key.starts_with(&prefix)),
            Box::new(move |key| {
                let value = storage_cloned.get(key).unwrap().unwrap();
                let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
                let output_index = u32::from_be_bytes(
                    key[key.len() - 4..]
                        .try_into()
                        .expect("stored output_index"),
                );
                let block_number = u64::from_be_bytes(
                    key[key.len() - 16..key.len() - 8]
                        .try_into()
                        .expect("stored block_number"),
                );

                let tx = packed::Transaction::from_slice(
                    &storage_cloned
                        .get(Key::TxHash(&tx_hash).into_vec())
                        .expect("get tx should be OK")
                        .expect("stored tx")[12..],
                )
                .expect("from stored tx slice should be OK");
                let output = tx
                    .raw()
                    .outputs()
                    .get(output_index as usize)
                    .expect("get output by index should be OK");
                let output_data = tx
                    .raw()
                    .outputs_data()
                    .get(output_index as usize)
                    .expect("get output data by index should be OK");

                if let Some(prefix) = filter_prefix.as_ref() {
                    match filter_script_type {
                        ScriptType::Lock => {
                            if !extract_raw_data(&output.lock())
                                .as_slice()
                                .starts_with(prefix)
                            {
                                log::trace!("break at {}", line!());
                                return None;
                            }
                        }
                        ScriptType::Type => {
                            if output.type_().is_none()
                                || !extract_raw_data(&output.type_().to_opt().unwrap())
                                    .as_slice()
                                    .starts_with(prefix)
                            {
                                log::trace!("break at {}", line!());
                                return None;
                            }
                        }
                    }
                }

                if let Some([r0, r1]) = filter_script_len_range {
                    match filter_script_type {
                        ScriptType::Lock => {
                            let script_len = extract_raw_data(&output.lock()).len();
                            if script_len < r0 || script_len > r1 {
                                log::trace!("break at {}", line!());
                                return None;
                            }
                        }
                        ScriptType::Type => {
                            let script_len = output
                                .type_()
                                .to_opt()
                                .map(|script| extract_raw_data(&script).len())
                                .unwrap_or_default();
                            if script_len < r0 || script_len > r1 {
                                log::trace!("break at {}", line!());
                                return None;
                            }
                        }
                    }
                }

                if let Some([r0, r1]) = filter_output_data_len_range
                    && (output_data.len() < r0 || output_data.len() >= r1)
                {
                    log::trace!("break at {}", line!());
                    return None;
                }

                if let Some([r0, r1]) = filter_output_capacity_range {
                    let capacity: core::Capacity = output.capacity().unpack();
                    if capacity < r0 || capacity >= r1 {
                        log::trace!("break at {}", line!());
                        return None;
                    }
                }

                if let Some([r0, r1]) = filter_block_range
                    && (block_number < r0 || block_number >= r1)
                {
                    log::trace!("break at {}", line!());
                    return None;
                }
                log::trace!("Returning normally at {:?}", key);
                Some(key.to_vec())
            }),
            usize::MAX,
            skip,
        );

        let mut capacity = 0;
        for (key, value) in kvs.into_iter() {
            let tx_hash = packed::Byte32::from_slice(&value).expect("stored tx hash");
            let output_index = u32::from_be_bytes(
                key[key.len() - 4..]
                    .try_into()
                    .expect("stored output_index"),
            );

            let tx = packed::Transaction::from_slice(
                &storage
                    .get(Key::TxHash(&tx_hash).into_vec())
                    .expect("get tx should be OK")
                    .expect("stored tx")[12..],
            )
            .expect("from stored tx slice should be OK");
            let output = tx
                .raw()
                .outputs()
                .get(output_index as usize)
                .expect("get output by index should be OK");
            capacity += Unpack::<core::Capacity>::unpack(&output.capacity()).as_u64()
        }

        let key = Key::Meta(LAST_STATE_KEY).into_vec();
        let tip_header = storage
            .get(key)
            .expect("snapshot get last state should be ok")
            .map(|data| packed::HeaderReader::from_slice_should_be_ok(&data[32..]).to_entity())
            .expect("tip header should be inited");
        log::trace!("Get cells capacity done");
        Ok(CellsCapacity {
            capacity: capacity.into(),
            block_hash: tip_header.calc_header_hash().unpack(),
            block_number: tip_header.raw().number().unpack(),
        })
    }
}

const MAX_PREFIX_SEARCH_SIZE: usize = u16::MAX as usize;

// a helper fn to build query options from search paramters, returns prefix, from_key, direction and skip offset
pub fn build_query_options(
    search_key: &SearchKey,
    lock_prefix: KeyPrefix,
    type_prefix: KeyPrefix,
    order: Order,
    after_cursor: Option<JsonBytes>,
) -> Result<(Vec<u8>, Vec<u8>, GeneralDirection, usize)> {
    let mut prefix = match search_key.script_type {
        ScriptType::Lock => vec![lock_prefix as u8],
        ScriptType::Type => vec![type_prefix as u8],
    };
    let script: packed::Script = search_key.script.clone().into();
    let args_len = script.args().len();
    if args_len > MAX_PREFIX_SEARCH_SIZE {
        return Err(Error::runtime(format!(
            "search_key.script.args len should be less than {}",
            MAX_PREFIX_SEARCH_SIZE
        )));
    }
    prefix.extend_from_slice(extract_raw_data(&script).as_slice());

    let (from_key, direction, skip) = match order {
        Order::Asc => after_cursor.map_or_else(
            || (prefix.clone(), GeneralDirection::Forward, 0),
            |json_bytes| (json_bytes.as_bytes().into(), GeneralDirection::Forward, 1),
        ),
        Order::Desc => after_cursor.map_or_else(
            || {
                (
                    [
                        prefix.clone(),
                        vec![0xff; MAX_PREFIX_SEARCH_SIZE - args_len],
                    ]
                    .concat(),
                    GeneralDirection::Reverse,
                    0,
                )
            },
            |json_bytes| (json_bytes.as_bytes().into(), GeneralDirection::Reverse, 1),
        ),
    };

    Ok((prefix, from_key, direction, skip))
}
use ckb_types::core;
use log::trace;

#[allow(clippy::type_complexity)]
pub fn build_filter_options(
    search_key: SearchKey,
) -> Result<(
    Option<Vec<u8>>,
    Option<[usize; 2]>,
    Option<[usize; 2]>,
    Option<[core::Capacity; 2]>,
    Option<[core::BlockNumber; 2]>,
)> {
    let filter = search_key.filter.unwrap_or_default();
    let filter_script_prefix = if let Some(script) = filter.script {
        let script: packed::Script = script.into();
        if script.args().len() > MAX_PREFIX_SEARCH_SIZE {
            return Err(Error::runtime(format!(
                "search_key.filter.script.args len should be less than {}",
                MAX_PREFIX_SEARCH_SIZE
            )));
        }
        let mut prefix = Vec::new();
        prefix.extend_from_slice(extract_raw_data(&script).as_slice());
        Some(prefix)
    } else {
        None
    };

    let filter_script_len_range = filter.script_len_range.map(|[r0, r1]| {
        [
            Into::<u64>::into(r0) as usize,
            Into::<u64>::into(r1) as usize,
        ]
    });

    let filter_output_data_len_range = filter.output_data_len_range.map(|[r0, r1]| {
        [
            Into::<u64>::into(r0) as usize,
            Into::<u64>::into(r1) as usize,
        ]
    });
    let filter_output_capacity_range = filter.output_capacity_range.map(|[r0, r1]| {
        [
            core::Capacity::shannons(r0.into()),
            core::Capacity::shannons(r1.into()),
        ]
    });
    let filter_block_range = filter.block_range.map(|r| [r[0].into(), r[1].into()]);

    Ok((
        filter_script_prefix,
        filter_script_len_range,
        filter_output_data_len_range,
        filter_output_capacity_range,
        filter_block_range,
    ))
}
