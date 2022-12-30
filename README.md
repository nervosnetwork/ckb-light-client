# CKB light client reference implementation

[![License]](#license)
[![GitHub Actions]](https://github.com/nervosnetwork/ckb-light-client/actions)
[![Codecov]](https://codecov.io/gh/nervosnetwork/ckb-light-client)

A CKB light client based on [RFC 44] and [RFC 45].

[License]: https://img.shields.io/badge/License-MIT-blue.svg
[GitHub Actions]: https://github.com/nervosnetwork/ckb-light-client/workflows/CI/badge.svg
[Codecov]: https://img.shields.io/codecov/c/gh/nervosnetwork/ckb-light-client/develop

## How to connect testnet

1. Run your own full node, this is an optional step, you may use the public testnet bootnodes instead.

Download ckb [v0.106.0 or above](https://github.com/nervosnetwork/ckb/releases/tag/v0.106.0), init and run ckb in a new folder:
```
ckb init -c testnet
ckb run
```

Get full node peer id
```
curl http://localhost:8114/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method":"local_node_info", "params": [], "id": 1}'
```

2. Build a light client with [this branch](https://github.com/nervosnetwork/ckb-light-client/tree/develop) or download the prebuilt binary.

```
git clone https://github.com/nervosnetwork/ckb-light-client.git
git checkout develop
cargo build --release
```

3. Run light client

Copy the `ckb-light-client` binary and `config/testnet.toml` to a new folder, if you want to connect to the full node you just build in step 1, modify the `bootnodes` section's peer address to full node peer's ip (should be 127.0.0.1 if you run the full node on localhost) and peer id.

Start light client:
```
RUST_LOG=info,ckb_light_client=info ./ckb-light-client run --config-file ./testnet.toml
```

## RPC

### `set_scripts`

Set some scripts to filter

#### Parameters

    script - Script
    script_type - Enum "lock" or "type"
    block_number - Filter start number

#### Returns

    null

#### Examples

```
curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method":"set_scripts", "params": [[{"script": {"code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", "hash_type": "type", "args": "0x50878ce52a68feb47237c29574d82288f58b5d21"}, "script_type": "lock", "block_number": "0x0"}]], "id": 1}'
```

### `get_scripts`

Get filter scripts status

#### Parameters

    null

#### Returns

    script - Script
    script_type - Enum "lock" or "type"
    block_number - Filtered block number

#### Examples

```
curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method":"get_scripts", "params": [], "id": 1}'
```

### `send_transaction`

Submits a new transaction and broadcast it to network peers

#### Parameters

    tx - Transaction

#### Returns

    tx_hash - H256

#### Examples

```
curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "send_transaction", "params": [{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}], "id": 1}'
```

### `get_tip_header`

Returns the header with the highest block number in the canonical chain

#### Parameters

    null

#### Returns

    header - HeaderView

#### Examples

```
curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "get_tip_header", "params": [], "id": 1}'
```

### `get_genesis_block`

Returns the genesis block

#### Parameters

    null

#### Returns

    block - BlockView

#### Examples

```
curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "get_genesis_block", "params": [], "id": 1}'
```

### `get_header`

Returns the information about a block header by hash.

#### Parameters

    block_hash - the block hash

#### Returns

    header - HeaderView

#### Examples

```
curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "get_header", "params": ["0xa5f5c85987a15de25661e5a214f2c1449cd803f071acc7999820f25246471f40"], "id": 1}'
```

### `get_transaction`

Returns the information about a transaction by hash, the block header is also returned.

#### Parameters

    transaction_hash - the transaction hash

#### Returns
    TransactionWithStatus struct fields:

    transaction -  TransactionView
    cycles - a optional field, cycles used by this transaction
    tx_status:
        status - enum "pending", "committed" or "unknown"
        block_hash - the block hash which contains this transaction, only available when status is "committed"

#### Examples

```
curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method": "get_transaction", "params": ["0xa0ef4eb5f4ceeb08a4c8524d84c5da95dce2f608e0ca2ec8091191b0f330c6e3"], "id": 1}'
```

### `fetch_header`

Fetch a header from remote node. If return status is `not_found` will re-sent fetching request immediately.

#### Parameters

    block_hash  - the block hash

#### Returns

    {"status": "fetched", "data": HeaderView }
    {"status": "fetching", "first_sent": Uint64 }
    {"status": "added", "timestamp": Uint64 }
    {"status": "not_found" }

### `fetch_transaction`

Fetch a transaction from remote node. If return status is `not_found` will re-sent fetching request immediately.

#### Parameters

    tx_hash  - the transaction hash

#### Returns

    {"status": "fetched", "data": TransactionWithStatus } // TransactionWithStatus is same as get_transaction rpc response
    {"status": "fetching", "first_sent": Uint64 }
    {"status": "added", "timestamp": Uint64 }
    {"status": "not_found" }

### `get_cells`

To facilitate code migration, the rpc is same as ckb-indexer, please refer to ckb-indexer rpc [doc](https://github.com/nervosnetwork/ckb-indexer#get_cells)

### `get_transactions`

To facilitate code migration, the rpc is similar as ckb-indexer, the only difference is the returning data, light client will return a full transaction struct, please refer to ckb-indexer rpc [doc](https://github.com/nervosnetwork/ckb-indexer#get_transactions)

### `get_cells_capacity`

To facilitate code migration, the rpc is same as ckb-indexer, please refer to ckb-indexer rpc [doc](https://github.com/nervosnetwork/ckb-indexer#get_cells_capacity)

## License

Licensed under [MIT License].

[RFC 44]: https://github.com/nervosnetwork/rfcs/pull/370
[RFC 45]: https://github.com/nervosnetwork/rfcs/pull/375
[MIT License]: LICENSE
