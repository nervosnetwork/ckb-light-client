use ckb_jsonrpc_types::{BlockNumber, Script};
use jsonrpc_core::{IoHandler, Result};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::{Server, ServerBuilder};
use jsonrpc_server_utils::cors::AccessControlAllowOrigin;
use jsonrpc_server_utils::hosts::DomainsValidation;
use std::net::ToSocketAddrs;

use crate::storage::Storage;

#[rpc(server)]
pub trait BlockFilterRpc {
    /// curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method":"set_scripts", "params": [[{"code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", "hash_type": "type", "args": "0x50878ce52a68feb47237c29574d82288f58b5d21"}], ["0x59F74D"]], "id": 1}'
    #[rpc(name = "set_scripts")]
    fn set_scripts(&self, scripts: Vec<Script>, block_numbers: Vec<BlockNumber>) -> Result<()>;
}

pub struct BlockFilterRpcImpl {
    storage: Storage,
}

impl BlockFilterRpc for BlockFilterRpcImpl {
    fn set_scripts(&self, scripts: Vec<Script>, block_numbers: Vec<BlockNumber>) -> Result<()> {
        let scripts = scripts
            .into_iter()
            .zip(block_numbers)
            .map(|(script, block_number)| (script.into(), block_number.into()))
            .collect();

        self.storage.update_filter_scripts(scripts);
        Ok(())
    }
}

pub struct Service {
    listen_address: String,
}

impl Service {
    pub fn new(listen_address: &str) -> Self {
        Self {
            listen_address: listen_address.to_string(),
        }
    }

    pub fn start(&self, storage: Storage) -> Server {
        let mut io_handler = IoHandler::new();
        let rpc_impl = BlockFilterRpcImpl { storage };
        io_handler.extend_with(rpc_impl.to_delegate());

        ServerBuilder::new(io_handler)
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Null,
                AccessControlAllowOrigin::Any,
            ]))
            .health_api(("/ping", "ping"))
            .start_http(
                &self
                    .listen_address
                    .to_socket_addrs()
                    .expect("config listen_address parsed")
                    .next()
                    .expect("config listen_address parsed"),
            )
            .expect("Start Jsonrpc HTTP service")
    }
}
