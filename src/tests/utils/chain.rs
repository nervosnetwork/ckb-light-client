use std::sync::Arc;

use ckb_app_config::{BlockAssemblerConfig, NetworkConfig};
use ckb_chain::chain::{ChainController, ChainService};
use ckb_chain_spec::{consensus::Consensus, ChainSpec};
use ckb_jsonrpc_types::ScriptHashType;
use ckb_launcher::SharedBuilder;
use ckb_network::{DefaultExitHandler, NetworkController, NetworkService, NetworkState};
use ckb_resource::Resource;
use ckb_shared::Shared;
use ckb_types::h256;

use crate::{storage::Storage, tests::prelude::*};

/// Mock a chain without starting services.
pub(crate) struct MockChain {
    storage: Storage,
    consensus: Consensus,
}

/// Mock a chain and start its services.
pub(crate) struct MockRunningChain {
    storage: Storage,
    chain_controller: ChainController,
    shared: Shared,
}

impl ChainExt for MockChain {
    fn client_storage(&self) -> &Storage {
        &self.storage
    }

    fn consensus(&self) -> &Consensus {
        &self.consensus
    }
}

impl ChainExt for MockRunningChain {
    fn client_storage(&self) -> &Storage {
        &self.storage
    }

    fn consensus(&self) -> &Consensus {
        &self.shared.consensus()
    }
}

impl RunningChainExt for MockRunningChain {
    fn controller(&self) -> &ChainController {
        &self.chain_controller
    }

    fn shared(&self) -> &Shared {
        &self.shared
    }
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

    pub(crate) fn new_with_dummy_pow(prefix: &str) -> Self {
        let resource = Resource::file_system("src/tests/specs/dummy_pow.toml".into());
        Self::new(&resource, prefix)
    }

    pub(crate) fn start(self) -> MockRunningChain {
        let Self { storage, consensus } = self;

        let config = BlockAssemblerConfig {
            code_hash: h256!("0x0"),
            args: Default::default(),
            hash_type: ScriptHashType::Data,
            message: Default::default(),
            use_binary_version_as_message_prefix: true,
            binary_version: "LightClient".to_string(),
            update_interval_millis: 800,
            notify: vec![],
            notify_scripts: vec![],
            notify_timeout_millis: 800,
        };

        let (shared, mut pack) = SharedBuilder::with_temp_db()
            .consensus(consensus)
            .block_assembler_config(Some(config))
            .build()
            .unwrap();

        let network = dummy_network(&shared);
        pack.take_tx_pool_builder().start(network);

        let chain_service = ChainService::new(shared.clone(), pack.take_proposal_table());
        let chain_controller = chain_service.start::<&str>(None);

        MockRunningChain {
            storage,
            chain_controller,
            shared,
        }
    }
}

fn dummy_network(shared: &Shared) -> NetworkController {
    let tmp_dir = tempfile::Builder::new().tempdir().unwrap();
    let config = NetworkConfig {
        max_peers: 19,
        max_outbound_peers: 5,
        path: tmp_dir.path().to_path_buf(),
        ping_interval_secs: 15,
        ping_timeout_secs: 20,
        connect_outbound_interval_secs: 1,
        discovery_local_address: true,
        bootnode_mode: true,
        reuse_port_on_linux: true,
        ..Default::default()
    };
    let network_state =
        Arc::new(NetworkState::from_config(config).expect("Init network state failed"));
    NetworkService::new(
        network_state,
        vec![],
        vec![],
        shared.consensus().identify_name(),
        "test".to_string(),
        DefaultExitHandler::default(),
    )
    .start(shared.async_handle())
    .expect("Start network service failed")
}
