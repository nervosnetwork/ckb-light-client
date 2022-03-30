use ckb_jsonrpc_types::{BlockNumber, Script};
use ckb_types::{core, packed};
use jsonrpc_core::{IoHandler, Result};
use jsonrpc_derive::rpc;
use jsonrpc_http_server::{Server, ServerBuilder};
use jsonrpc_server_utils::cors::AccessControlAllowOrigin;
use jsonrpc_server_utils::hosts::DomainsValidation;
use std::net::ToSocketAddrs;
use std::sync::{Arc, RwLock};

#[rpc(server)]
pub trait BlockFilterRpc {
    /// curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method":"set_scripts", "params": [[{"code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", "hash_type": "type", "args": "0x50878ce52a68feb47237c29574d82288f58b5d21"}], "0x59F74D"], "id": 1}'
    #[rpc(name = "set_scripts")]
    fn set_scripts(&self, scripts: Vec<Script>, block_number: Option<BlockNumber>) -> Result<()>;
}

pub struct BlockFilterRpcImpl {
    script_hashes_and_block_number: Arc<RwLock<(Vec<packed::Byte32>, core::BlockNumber)>>,
}

impl BlockFilterRpc for BlockFilterRpcImpl {
    fn set_scripts(&self, scripts: Vec<Script>, block_number: Option<BlockNumber>) -> Result<()> {
        let mut script_hashes_and_block_number =
            self.script_hashes_and_block_number.write().unwrap();
        script_hashes_and_block_number.0 = scripts
            .into_iter()
            .map(|script| {
                let s: packed::Script = script.into();
                s.calc_script_hash()
            })
            .collect();
        script_hashes_and_block_number.1 = block_number.unwrap_or_default().into();
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

    pub fn start(
        &self,
        script_hashes_and_block_number: Arc<RwLock<(Vec<packed::Byte32>, core::BlockNumber)>>,
    ) -> Server {
        let mut io_handler = IoHandler::new();
        let rpc_impl = BlockFilterRpcImpl {
            script_hashes_and_block_number,
        };
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
