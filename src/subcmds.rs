use std::sync::{Arc, RwLock};

use ckb_async_runtime::new_global_runtime;
use ckb_chain_spec::ChainSpec;
use ckb_network::{
    tokio, CKBProtocol, CKBProtocolHandler, Flags, NetworkService, NetworkState, SupportProtocols,
};
use ckb_resource::Resource;
use ckb_stop_handler::{broadcast_exit_signals, wait_all_ckb_services_exit};
use log::debug;

use crate::{
    config::RunConfig,
    error::{Error, Result},
    protocols::{
        FilterProtocol, LightClientProtocol, Peers, PendingTxs, RelayProtocol, SyncProtocol,
        CHECK_POINT_INTERVAL,
    },
    service::Service,
    storage::Storage,
    utils,
};

impl RunConfig {
    pub(crate) fn execute(self) -> Result<()> {
        log::info!("Run ...");

        utils::fs::need_directory(&self.run_env.network.path)?;

        let storage = Storage::new(&self.run_env.store.path);
        let chain_spec = ChainSpec::load_from(&match self.run_env.chain.as_str() {
            "mainnet" => Resource::bundled("specs/mainnet.toml".to_string()),
            "testnet" => Resource::bundled("specs/testnet.toml".to_string()),
            path => Resource::file_system(path.into()),
        })
        .expect("load spec should be OK");
        let consensus = chain_spec
            .build_consensus()
            .expect("build consensus should be OK");
        storage.init_genesis_block(consensus.genesis_block().data());

        let pending_txs = Arc::new(RwLock::new(PendingTxs::default()));
        let max_outbound_peers = self.run_env.network.max_outbound_peers;
        let network_state = NetworkState::from_config(self.run_env.network)
            .map(|network_state| {
                Arc::new(network_state.required_flags(
                    Flags::DISCOVERY
                        | Flags::SYNC
                        | Flags::RELAY
                        | Flags::LIGHT_CLIENT
                        | Flags::BLOCK_FILTER,
                ))
            })
            .map_err(|err| {
                let errmsg = format!("failed to initialize network state since {}", err);
                Error::runtime(errmsg)
            })?;
        let required_protocol_ids = vec![
            SupportProtocols::Sync.protocol_id(),
            SupportProtocols::LightClient.protocol_id(),
            SupportProtocols::Filter.protocol_id(),
        ];

        let peers = Arc::new(Peers::new(
            max_outbound_peers,
            CHECK_POINT_INTERVAL,
            storage.get_last_check_point(),
        ));
        let sync_protocol = SyncProtocol::new(storage.clone(), Arc::clone(&peers));
        let relay_protocol_v2 = RelayProtocol::new(
            pending_txs.clone(),
            Arc::clone(&peers),
            consensus.clone(),
            false,
        );
        let relay_protocol_v3 = RelayProtocol::new(
            pending_txs.clone(),
            Arc::clone(&peers),
            consensus.clone(),
            true,
        );
        let light_client: Box<dyn CKBProtocolHandler> = Box::new(LightClientProtocol::new(
            storage.clone(),
            Arc::clone(&peers),
            consensus.clone(),
        ));
        let filter_protocol = FilterProtocol::new(storage.clone(), Arc::clone(&peers));

        let protocols = vec![
            CKBProtocol::new_with_support_protocol(
                SupportProtocols::Sync,
                Box::new(sync_protocol),
                Arc::clone(&network_state),
            ),
            CKBProtocol::new_with_support_protocol(
                SupportProtocols::RelayV2,
                Box::new(relay_protocol_v2),
                Arc::clone(&network_state),
            ),
            CKBProtocol::new_with_support_protocol(
                SupportProtocols::RelayV3,
                Box::new(relay_protocol_v3),
                Arc::clone(&network_state),
            ),
            CKBProtocol::new_with_support_protocol(
                SupportProtocols::LightClient,
                light_client,
                Arc::clone(&network_state),
            ),
            CKBProtocol::new_with_support_protocol(
                SupportProtocols::Filter,
                Box::new(filter_protocol),
                Arc::clone(&network_state),
            ),
        ];

        let (mut handle, mut handle_stop_rx, _stop_handler) = new_global_runtime();

        let network_controller = NetworkService::new(
            Arc::clone(&network_state),
            protocols,
            required_protocol_ids,
            (
                consensus.identify_name(),
                clap::crate_version!().to_owned(),
                Flags::DISCOVERY,
            ),
        )
        .start(&handle)
        .map_err(|err| {
            let errmsg = format!("failed to start network since {}", err);
            Error::runtime(errmsg)
        })?;

        let service = Service::new(&self.run_env.rpc.listen_address);
        let rpc_server = service.start(network_controller, storage, peers, pending_txs, consensus);

        ctrlc::set_handler(move || {
            broadcast_exit_signals();
        })
        .map_err(|err| {
            let errmsg = format!("failed to set Ctrl-C handler since {}", err);
            Error::runtime(errmsg)
        })?;

        wait_all_ckb_services_exit();

        handle.drop_guard();
        rpc_server.close();

        tokio::task::block_in_place(|| {
            debug!("Waiting all tokio tasks finished ...");
            handle_stop_rx.blocking_recv();
        });

        Ok(())
    }
}
