use ckb_network::tokio;
use ckb_stop_handler::{broadcast_exit_signals, wait_all_ckb_services_exit};
use log::debug;

use ckb_light_client_lib::{
    error::{Error, Result},
    runtime::StartedLightClient,
};

use crate::{cli::RunConfig, rpc::Service};

impl RunConfig {
    pub(crate) fn execute(self) -> Result<()> {
        log::info!("Run ...");

        let mut client = StartedLightClient::start(self.run_env.clone())?;

        let service = Service::new(&self.run_env.rpc.listen_address);
        let rpc_server = service.start(
            client.network_controller(),
            client.storage(),
            client.peers(),
            client.pending_txs(),
            client.consensus(),
        );

        ctrlc::set_handler(move || {
            broadcast_exit_signals();
        })
        .map_err(|err| {
            let errmsg = format!("failed to set Ctrl-C handler since {}", err);
            Error::runtime(errmsg)
        })?;

        wait_all_ckb_services_exit();

        client.runtime_handle().drop_guard();
        rpc_server.close();

        tokio::task::block_in_place(|| {
            debug!("Waiting all tokio tasks finished ...");
            client.stop_receiver().blocking_recv();
        });

        Ok(())
    }
}
