//! External public-API example for this proposal, not an existing consumer.
#![cfg(not(target_arch = "wasm32"))]

use std::sync::{Arc, RwLock};

use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_light_client_lib::{
    error::Result,
    protocols::{Peers, PendingTxs},
    service::{FetchStatus, HeaderRevalidationHandle, LightClientChainService},
    storage::{LightClientStorage, Storage, StorageWithChainData},
};
use ckb_types::{core, H256, U256};

// This function compiles as an external crate using only the proposed public API.
fn start_and_poll(
    service: &LightClientChainService,
    hash: &H256,
) -> Result<FetchStatus<ckb_jsonrpc_types::HeaderView>> {
    let handle: HeaderRevalidationHandle = service.revalidate_header(hash)?;
    handle.status()
}

#[test]
fn public_handle_binds_at_creation_and_polls_immutably() {
    let directory = tempfile::tempdir().unwrap();
    let storage = Storage::new(directory.path());
    let tip = core::HeaderBuilder::default()
        .number(20u64)
        .epoch(core::EpochNumberWithFraction::new(0, 20, 1000))
        .build();
    storage.update_last_state(&U256::from(20u64), &tip.data(), &[]);
    let peers = Arc::new(Peers::new(1, 1, (0, Default::default()), 0));
    let service = LightClientChainService::new(
        StorageWithChainData::new(
            storage,
            Arc::clone(&peers),
            Arc::new(RwLock::new(PendingTxs::default())),
        ),
        Arc::new(ConsensusBuilder::default().build()),
    );
    let hash = H256::default();
    assert!(matches!(
        start_and_poll(&service, &hash).unwrap(),
        FetchStatus::Added { .. }
    ));
    let handle = service.revalidate_header(&hash).unwrap();
    let poll: fn(&HeaderRevalidationHandle) -> Result<FetchStatus<ckb_jsonrpc_types::HeaderView>> =
        HeaderRevalidationHandle::status;
    assert!(matches!(poll(&handle).unwrap(), FetchStatus::Added { .. }));
    let clone = service.clone();
    drop(service);
    assert!(matches!(
        handle.status().unwrap(),
        FetchStatus::Added { .. }
    ));
    drop(clone);
    // Even a still-live Peers owner does not let this handle adopt another client.
    assert!(Arc::strong_count(&peers) > 0);
    assert!(handle.status().is_err());
}
