use ckb_network::{bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex};
use ckb_types::core::{Cycle, TransactionView};
use ckb_types::{packed, prelude::*};
use log::{info, trace, warn};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};
use std::time::Duration;

pub const BAD_MESSAGE_BAN_TIME: Duration = Duration::from_secs(5 * 60);

pub(crate) struct RelayProtocol {
    pending_txs: Arc<RwLock<PendingTxs>>,
}

// a simple struct to store the pending transactions in memory with size limit
pub(crate) struct PendingTxs {
    txs: HashMap<packed::Byte32, (packed::Transaction, Cycle)>,
    tx_hashes: VecDeque<packed::Byte32>,
    limit: usize,
}

impl PendingTxs {
    pub fn new(limit: usize) -> Self {
        Self {
            txs: HashMap::new(),
            tx_hashes: VecDeque::new(),
            limit,
        }
    }

    pub fn push(&mut self, tx: TransactionView, cycles: Cycle) {
        self.txs.insert(tx.hash(), (tx.data(), cycles));
        self.tx_hashes.push_back(tx.hash());
        if self.tx_hashes.len() > self.limit {
            self.tx_hashes
                .pop_front()
                .and_then(|hash| self.txs.remove(&hash));
        }
    }

    fn get(&self, hash: packed::Byte32) -> Option<(packed::Transaction, Cycle)> {
        self.txs.get(&hash).cloned()
    }
}

impl RelayProtocol {
    pub fn new(pending_txs: Arc<RwLock<PendingTxs>>) -> Self {
        Self { pending_txs }
    }
}

impl CKBProtocolHandler for RelayProtocol {
    fn init(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>) {}

    fn connected(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        version: &str,
    ) {
        info!("RelayProtocol({}).connected peer={}", version, peer);
    }

    fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex) {
        info!("RelayProtocol.disconnected peer={}", peer);
    }

    fn received(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex, data: Bytes) {
        trace!("RelayProtocol.received peer={}", peer);

        let message = match packed::RelayMessageReader::from_compatible_slice(&data) {
            Ok(msg) => msg.to_enum(),
            _ => {
                warn!(
                    "RelayProtocol.received a malformed message from Peer({})",
                    peer
                );
                nc.ban_peer(
                    peer,
                    BAD_MESSAGE_BAN_TIME,
                    String::from("send us a malformed message"),
                );
                return;
            }
        };

        if let packed::RelayMessageUnionReader::GetRelayTransactions(reader) = message {
            let pending_txs = self.pending_txs.read().expect("read access should be OK");
            let relay_txs: Vec<_> = reader
                .tx_hashes()
                .iter()
                .filter_map(|tx_hash| {
                    pending_txs.get(tx_hash.to_entity()).map(|(tx, cycles)| {
                        packed::RelayTransaction::new_builder()
                            .transaction(tx)
                            .cycles(cycles.pack())
                            .build()
                    })
                })
                .collect();

            let content = packed::RelayTransactions::new_builder()
                .transactions(relay_txs.pack())
                .build();
            let msg = packed::RelayMessage::new_builder().set(content).build();
            if let Err(err) = nc.send_message_to(peer, msg.as_bytes()) {
                warn!(
                    "RelayProtocol failed to send RelayTransactions message to peer={} since {:?}",
                    peer, err
                );
            }
        } else {
            // ignore other messages
        }
    }
}
