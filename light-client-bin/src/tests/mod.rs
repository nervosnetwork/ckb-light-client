mod service;

use ckb_chain_spec::{consensus::Consensus, ChainSpec};
use ckb_light_client_lib::{
    protocols::{Peers, CHECK_POINT_INTERVAL},
    storage::Storage,
};
use ckb_resource::Resource;

use std::sync::Arc;

pub(crate) fn new_storage(prefix: &str) -> Storage {
    let tmp_dir = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
    Storage::new(tmp_dir.path().to_str().unwrap())
}

pub(crate) fn create_peers() -> Arc<Peers> {
    let max_outbound_peers = 1;
    let bad_message_allowed_each_hour = 0;
    let peers = Peers::new(
        max_outbound_peers,
        CHECK_POINT_INTERVAL,
        (0, Default::default()),
        bad_message_allowed_each_hour,
    );
    Arc::new(peers)
}

/// Mock a chain without starting services.
pub(crate) struct MockChain {
    storage: Storage,
    consensus: Consensus,
}

impl MockChain {
    pub(crate) fn new(resource: &Resource, prefix: &str) -> Self {
        let tmp_dir = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
        let storage = Storage::new(tmp_dir.path().to_str().unwrap());
        let chain_spec = ChainSpec::load_from(resource).expect("load spec should be OK");
        let consensus = chain_spec
            .build_consensus()
            .expect("build consensus should be OK");
        storage.init_genesis_block(consensus.genesis_block().data());
        MockChain { storage, consensus }
    }

    pub(crate) fn new_with_default_pow(prefix: &str) -> Self {
        // TODO Replace this to a devchain with "EaglesongBlake2b" pow.
        let resource = Resource::bundled("specs/testnet.toml".to_owned());
        Self::new(&resource, prefix)
    }

    pub(crate) fn client_storage(&self) -> &Storage {
        &self.storage
    }

    pub(crate) fn consensus(&self) -> &Consensus {
        &self.consensus
    }
}
