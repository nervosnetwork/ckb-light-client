import { expect, test } from "@jest/globals";
import { cccOrderToLightClientWasmOrder, FetchResponse, GetCellsResponse, getCellsResponseFrom, GetTransactionsResponse, lightClientGetTransactionsResultTo, LightClientLocalNode, LightClientOrder, LightClientRemoteNode, LightClientScriptStatus, LightClientTxWithCell, LightClientTxWithCells, LocalNode, localNodeTo, RemoteNode, remoteNodeTo, scriptStatusFrom, scriptStatusTo, transformFetchResponse, TxWithCell, TxWithCells } from "./types";
import { CellOutput, OutPoint, Transaction } from "@ckb-ccc/core";
test("test transform fetch response", () => {
    const a: FetchResponse<number> = { status: "fetched", data: 1 };
    const b: FetchResponse<number> = { status: "added", timestamp: BigInt("0") };
    const fn = (a: number) => a + 1;
    expect(transformFetchResponse(a, fn)).toStrictEqual({ status: "fetched", data: 2 });
    expect(transformFetchResponse(b, fn)).toStrictEqual(b);
})

test("test scriptStatusTo/From", () => {
    const raw: LightClientScriptStatus = {
        script: {
            code_hash: "0xabcd1234",
            hash_type: "data",
            args: "0x0011223344"
        },
        script_type: "lock",
        block_number: "0x1234"
    };
    const transformed = scriptStatusTo(raw);

    expect(scriptStatusFrom(transformed)).toStrictEqual(raw);
});

test("test remoteNodeTo", () => {
    const raw: LightClientRemoteNode = {
        version: "1",
        node_id: "111",
        addresses: [
            { address: "test", score: BigInt("123") }
        ],
        connected_duration: "0x234",
        protocols: [
            { id: BigInt("1"), version: "1" }
        ],
        sync_state: {
            proved_best_known_header: {
                compact_target: "0x12",
                dao: "0x04d0bc8a6028d30c0000c16ff286230066cbed490e00000000a38cdc1afbfe06",
                epoch: "0x11112222333333",
                extra_hash: "0x45",
                hash: "0x56",
                nonce: "0x67",
                number: "0x78",
                parent_hash: "0x89",
                proposals_hash: "0x90",
                timestamp: "0xab",
                transactions_root: "0xbc",
                version: "0xcd"
            }
        }
    };
    const newVal: RemoteNode = {
        version: "1",
        nodeId: "111",
        addresses: [
            { address: "test", score: BigInt("123") }
        ],
        connestedDuration: BigInt("0x234"),
        protocols: [
            { id: BigInt("1"), version: "1" }
        ],
        syncState: {
            provedBestKnownHeader: {
                compactTarget: BigInt("0x12"),
                dao: {
                    c: BigInt("924126743650684932"),
                    ar: BigInt("10000000000000000"),
                    s: BigInt("61369863014"),
                    u: BigInt("504116301100000000")
                },
                epoch: [BigInt("3355443"), BigInt("8738"), BigInt("4369")],
                extraHash: "0x45",
                hash: "0x56",
                nonce: BigInt("0x67"),
                number: BigInt("0x78"),
                parentHash: "0x89",
                proposalsHash: "0x90",
                timestamp: BigInt("0xab"),
                transactionsRoot: "0xbc",
                version: BigInt("0xcd")
            },
            requestedBestKnownHeader: undefined
        }
    };
    expect(remoteNodeTo(raw)).toStrictEqual(newVal);
});

test("test localNodeTo", () => {
    const raw: LightClientLocalNode = {
        version: "aaa",
        node_id: "bbb",
        active: false,
        addresses: [
            { address: "111", score: BigInt("123") }
        ],
        protocols: [
            { id: BigInt("1"), name: "test", support_version: ["a", "b", "c"] }
        ],
        connections: BigInt("123")
    }
    const expectedVal: LocalNode = {
        version: "aaa",
        nodeId: "bbb",
        active: false,
        addresses: [
            { address: "111", score: BigInt("123") }
        ],
        protocols: [
            { id: BigInt("1"), name: "test", supportVersion: ["a", "b", "c"] }
        ],
        connections: BigInt("123")
    };
    expect(localNodeTo(raw)).toStrictEqual(expectedVal);
});

test("test cccOrderToLightClientWasmOrder", () => {
    expect(cccOrderToLightClientWasmOrder("asc")).toBe(LightClientOrder.Asc);
    expect(cccOrderToLightClientWasmOrder("desc")).toBe(LightClientOrder.Desc);
});

test("test lightClientGetTransactionsResultTo", () => {
    expect(lightClientGetTransactionsResultTo({ last_cursor: "0x1234", objects: [] })).toStrictEqual({ lastCursor: "0x1234", transactions: [] });
    expect(lightClientGetTransactionsResultTo({
        last_cursor: "0x1234", objects: [
            {
                block_number: "0x1234",
                io_index: 1234,
                io_type: "input",
                transaction: {
                    cell_deps: [],
                    header_deps: [],
                    inputs: [],
                    outputs: [],
                    outputs_data: [],
                    version: "0x123",
                    witnesses: ["0x"]
                },
                tx_index: 2222
            } as LightClientTxWithCell
        ]
    })).toStrictEqual({
        lastCursor: "0x1234",
        transactions: [
            {
                blockNumber: BigInt("0x1234"),
                ioIndex: BigInt("1234"),
                ioType: "input",
                transaction: Transaction.from({
                    cellDeps: [],
                    headerDeps: [],
                    inputs: [],
                    outputs: [],
                    outputsData: [],
                    version: BigInt("0x123"),
                    witnesses: ["0x"]
                }),
                txIndex: BigInt("2222")
            }
        ]
    } as GetTransactionsResponse<TxWithCell>);

    expect(lightClientGetTransactionsResultTo({
        last_cursor: "0x1234", objects: [
            {
                block_number: "0x1234",
                tx_index: 123,
                transaction: {
                    cell_deps: [],
                    header_deps: [],
                    inputs: [],
                    outputs: [],
                    outputs_data: [],
                    version: "0x123",
                    witnesses: ["0x"]
                },
                cells: [
                    ["input", 111]
                ]
            } as LightClientTxWithCells
        ]
    })).toStrictEqual({
        lastCursor: "0x1234",
        transactions: [
            {
                blockNumber: BigInt("0x1234"),
                txIndex: BigInt("123"),
                transaction: Transaction.from({
                    cellDeps: [],
                    headerDeps: [],
                    inputs: [],
                    outputs: [],
                    outputsData: [],
                    version: BigInt("0x123"),
                    witnesses: ["0x"]
                }),
                cells: [
                    ["input", 111]
                ]
            }
        ]
    } as GetTransactionsResponse<TxWithCells>);
});

test("test getCellsResponseFrom", () => {
    const lhsValue = getCellsResponseFrom({
        last_cursor: "0x12345678",
        objects: [{
            block_number: "0x2345",
            tx_index: "0x9999",
            out_point: {
                index: "0x11112222",
                tx_hash: "0x23456789"
            },
            output: {
                capacity: "0x111",
                lock: {
                    args: "0x2345",
                    code_hash: "0x2222",
                    hash_type: "data"
                }
            }
        }]
    });
    const rhsValue: GetCellsResponse = {
        lastCursor: "0x12345678",
        cells: [{
            blockNumber: BigInt("9029"),
            txIndex: BigInt("39321"),
            outPoint: OutPoint.from({
                index: BigInt("0x11112222"),
                txHash: "0x23456789"
            }),
            outputData: "0x",
            cellOutput: CellOutput.from({
                capacity: BigInt("0x111"),
                lock: {
                    args: "0x2345",
                    codeHash: "0x2222",
                    hashType: "data"
                }
            })
        }]
    }
    expect(lhsValue).toStrictEqual(rhsValue);
});
