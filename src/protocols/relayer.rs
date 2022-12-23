use ckb_network::SupportProtocols;
use ckb_network::{
    async_trait, bytes::Bytes, extract_peer_id, CKBProtocolContext, CKBProtocolHandler, PeerId,
    PeerIndex,
};
use ckb_types::core::{Cycle, TransactionView};
use ckb_types::{packed, prelude::*};
use linked_hash_map::LinkedHashMap;
use log::{debug, trace, warn};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::protocols::{Peers, BAD_MESSAGE_BAN_TIME};

const CHECK_PENDING_TXS_TOKEN: u64 = 0;

pub(crate) struct RelayProtocol {
    connected_peers: Arc<Peers>,
    // Record the peers which have opened the relay protocol, value is used to close the protocol in the inactive period
    opened_peers: HashMap<PeerIndex, Option<Instant>>,
    // Pending transactions which are waiting for relay
    pending_txs: Arc<RwLock<PendingTxs>>,
}

// a simple struct to store the pending transactions in memory with size limit
pub(crate) struct PendingTxs {
    txs: LinkedHashMap<packed::Byte32, (packed::Transaction, Cycle, HashSet<PeerId>)>,
    updated_at: Instant,
    limit: usize,
}

impl PendingTxs {
    pub fn new(limit: usize) -> Self {
        Self {
            txs: LinkedHashMap::new(),
            updated_at: Instant::now(),
            limit,
        }
    }

    pub fn push(&mut self, tx: TransactionView, cycles: Cycle) {
        self.txs
            .insert(tx.hash(), (tx.data(), cycles, HashSet::new()));
        if self.txs.len() > self.limit {
            self.txs.pop_front();
        }
        self.updated_at = Instant::now();
    }

    pub fn get(
        &self,
        hash: &packed::Byte32,
    ) -> Option<(packed::Transaction, Cycle, HashSet<PeerId>)> {
        self.txs.get(hash).cloned()
    }

    fn fetch_transaction_hashes_for_broadcast(&mut self, peer_id: PeerId) -> Vec<packed::Byte32> {
        self.txs
            .iter_mut()
            .filter_map(|(hash, (_, _, peers))| {
                if peers.insert(peer_id.clone()) {
                    Some(hash.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    fn is_not_empty_and_updated_at(&self, seconds: u64) -> bool {
        !self.txs.is_empty() && self.updated_at.elapsed() < Duration::from_secs(seconds)
    }
}

impl RelayProtocol {
    pub fn new(pending_txs: Arc<RwLock<PendingTxs>>, connected_peers: Arc<Peers>) -> Self {
        Self {
            opened_peers: HashMap::new(),
            pending_txs,
            connected_peers,
        }
    }
}

#[async_trait]
impl CKBProtocolHandler for RelayProtocol {
    async fn init(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>) {
        nc.set_notify(Duration::from_secs(2), CHECK_PENDING_TXS_TOKEN)
            .await
            .expect("set_notify should be ok");
    }

    async fn connected(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        version: &str,
    ) {
        debug!("RelayProtocol({}).connected peer={}", version, peer);
        if self
            .pending_txs
            .read()
            .unwrap()
            .is_not_empty_and_updated_at(60)
        {
            let peer_id = nc
                .get_peer(peer)
                .and_then(|p| extract_peer_id(&p.connected_addr))
                .unwrap();
            let tx_hashes = self
                .pending_txs
                .write()
                .unwrap()
                .fetch_transaction_hashes_for_broadcast(peer_id);
            if !tx_hashes.is_empty() {
                let content = packed::RelayTransactionHashes::new_builder()
                    .tx_hashes(tx_hashes.pack())
                    .build();
                let message = packed::RelayMessage::new_builder().set(content).build();

                if let Err(err) = nc.send_message(
                    SupportProtocols::RelayV2.protocol_id(),
                    peer,
                    message.as_bytes(),
                ) {
                    warn!(
                        "RelayProtocol failed to send RelayTransactionHashes message to peer={} since {:?}",
                        peer, err
                    );
                }
                self.opened_peers.insert(peer, Some(Instant::now()));
            } else {
                self.opened_peers.insert(peer, None);
            }
        } else {
            self.opened_peers.insert(peer, None);
        }
    }

    async fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex) {
        debug!("RelayProtocol.disconnected peer={}", peer);
        self.opened_peers.remove(&peer);
    }

    async fn received(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        data: Bytes,
    ) {
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

        trace!(
            "RelayProtocol.received peer={}, message={}",
            peer,
            message.item_name()
        );
        if let packed::RelayMessageUnionReader::GetRelayTransactions(reader) = message {
            let pending_txs = self.pending_txs.read().expect("read access should be OK");
            let relay_txs: Vec<_> = reader
                .tx_hashes()
                .iter()
                .filter_map(|tx_hash| {
                    pending_txs
                        .get(&tx_hash.to_entity())
                        .map(|(tx, cycles, _)| {
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

    async fn notify(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>, token: u64) {
        match token {
            CHECK_PENDING_TXS_TOKEN => {
                // we check pending txs every 2 seconds, if the timestamp of the pending txs is updated in the last minute
                // and connected relay protocol peers is empty, we try to open the protocol and broadcast the pending txs
                if self
                    .pending_txs
                    .read()
                    .unwrap()
                    .is_not_empty_and_updated_at(60)
                    && self.opened_peers.is_empty()
                {
                    let p2p_control = nc.p2p_control().expect("p2p_control should be exist");
                    for peer in self.connected_peers.get_peers_index() {
                        if let Err(err) =
                            p2p_control.open_protocol(peer, SupportProtocols::RelayV2.protocol_id())
                        {
                            warn!(
                                "RelayProtocol failed to open protocol to peer={} since {:?}",
                                peer, err
                            );
                        }
                    }
                } else {
                    let mut pending_txs = self.pending_txs.write().unwrap();
                    for (&peer, instant) in self.opened_peers.iter_mut() {
                        if let Some(peer_id) = nc
                            .get_peer(peer)
                            .and_then(|p| extract_peer_id(&p.connected_addr))
                        {
                            let tx_hashes =
                                pending_txs.fetch_transaction_hashes_for_broadcast(peer_id);
                            if !tx_hashes.is_empty() {
                                let content = packed::RelayTransactionHashes::new_builder()
                                    .tx_hashes(tx_hashes.pack())
                                    .build();
                                let message =
                                    packed::RelayMessage::new_builder().set(content).build();

                                if let Err(err) = nc.send_message(
                                    SupportProtocols::RelayV2.protocol_id(),
                                    peer,
                                    message.as_bytes(),
                                ) {
                                    warn!(
                                        "RelayProtocol failed to send RelayTransactionHashes message to peer={} since {:?}",
                                        peer, err
                                    );
                                }
                                instant.replace(Instant::now());
                            } else if instant
                                .map(|i| i.elapsed() > Duration::from_secs(60))
                                .unwrap_or(true)
                            {
                                debug!(
                                    "RelayProtocol.notify peer={} is inactive, close the protocol",
                                    peer
                                );
                                let _ = nc
                                    .p2p_control()
                                    .expect("p2p_control should be exist")
                                    .close_protocol(peer, SupportProtocols::RelayV2.protocol_id());
                            }
                        }
                    }
                }
            }
            _ => {
                unreachable!()
            }
        }
    }
}
