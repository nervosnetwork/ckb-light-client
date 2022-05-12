# [Experimental] CKB Light Client

[![License]](#license)
[![GitHub Actions]](https://github.com/yangby-cryptape/ckb-light-client/actions)

> :warning: **WARNING** This repository is unavailable, since it's still in
> the proof-of-concept stage.

A CKB light client based on [FlyClient].

[License]: https://img.shields.io/badge/License-MIT-blue.svg
[GitHub Actions]: https://github.com/yangby-cryptape/ckb-light-client/workflows/CI/badge.svg

## References

- [FlyClient: Super-Light Clients for Cryptocurrencies]
- [Merkle Mountain Ranges]

## How to connect testnet

1. Build a full node with [this branch](https://github.com/yangby-cryptape/ckb/tree/poc/light-client)

```
git clone https://github.com/yangby-cryptape/ckb.git
git checkout poc/light-client
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

3. Build a light client with [this branch](https://github.com/yangby-cryptape/ckb-light-client/tree/develop)

```
git clone https://github.com/yangby-cryptape/ckb-light-client.git
git checkout develop
cargo build --release
```

4. Run light client

get full node peer id
```
curl http://localhost:8114/ -X POST -H "Content-Type: application/json" -d '{"jsonrpc": "2.0", "method":"local_node_info", "params": [], "id": 1}'
```

copy `config.toml` to new folder and modify the `bootnodes`, `whitelist_peers` to full node peer's ip (should be 127.0.0.1 if you run the full node on localhost) and peer id.

modify the `config.toml` chain config to

```
chain = "/ckb_testnet/10639e08"
```

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
