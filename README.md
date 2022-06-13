# [Experimental] CKB Light Client

[![License]](#license)
[![GitHub Actions]](https://github.com/nervosnetwork/ckb-light-client/actions)

> :warning: **WARNING** This repository is unavailable, since it's still in
> the proof-of-concept stage.

A CKB light client based on [FlyClient].

[License]: https://img.shields.io/badge/License-MIT-blue.svg
[GitHub Actions]: https://github.com/nervosnetwork/ckb-light-client/workflows/CI/badge.svg

## References

- [FlyClient: Super-Light Clients for Cryptocurrencies]
- [Merkle Mountain Ranges]

## How to connect testnet

1. Build a full node with [this branch](https://github.com/nervosnetwork/ckb/tree/light-client)

```
git clone https://github.com/nervosnetwork/ckb.git
git checkout light-client
make prod
```

2. Run a testnet with light client protocols

init ckb in a new folder:
```
ckb init -c testnet
```

modify ckb.toml, add a line `block_filter_enable = true` to the section of `[store]` and start ckb
```
ckb run
```

3. Build a light client with [this branch](https://github.com/nervosnetwork/ckb-light-client/tree/develop)

```
git clone https://github.com/nervosnetwork/ckb-light-client.git
git checkout develop
cargo build --release
```

4. Run light client

get full node peer id
```
curl http://localhost:8114/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method":"local_node_info", "params": [], "id": 1}'
```

copy `config.toml` to new folder and modify the `bootnodes`, `whitelist_peers` to full node peer's ip (should be 127.0.0.1 if you run the full node on localhost) and peer id.

start light client
```
RUST_LOG=info,ckb_light_client=trace ./ckb-light-client run --config-file ./config.toml
```

## RPC

### `set_scripts`

Set some scripts to filter

#### Parameters

    script - Script
    block_number - Filter start number

#### Returns

    null

#### Examples

```
curl http://localhost:9000/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method":"set_scripts", "params": [[{"script": {"code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8", "hash_type": "type", "args": "0x50878ce52a68feb47237c29574d82288f58b5d21"}, "block_number": "0x0"}]], "id": 1}'
```

### `get_scripts`

Get filter scripts status

#### Parameters

    null

#### Returns

    script - Script
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

### `get_cells`

To facilitate code migration, the rpc is same as ckb-indexer, please refer to ckb-indexer rpc [doc](https://github.com/nervosnetwork/ckb-indexer#get_cells)

### `get_transactions`

To facilitate code migration, the rpc is similar as ckb-indexer, the only difference is the returning data, light client will return a full transaction struct, please refer to ckb-indexer rpc [doc](https://github.com/nervosnetwork/ckb-indexer#get_transactions)

### `get_cells_capacity`

To facilitate code migration, the rpc is same as ckb-indexer, please refer to ckb-indexer rpc [doc](https://github.com/nervosnetwork/ckb-indexer#get_cells_capacity)

## License

Licensed under [MIT License].

[FlyClient]: https://eprint.iacr.org/2019/226.pdf
[FlyClient: Super-Light Clients for Cryptocurrencies]: https://eprint.iacr.org/2019/226.pdf
[Merkle Mountain Ranges]: https://github.com/opentimestamps/opentimestamps-server/blob/master/doc/merkle-mountain-range.md

[MIT License]: LICENSE
