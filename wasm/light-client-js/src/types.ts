import { numFrom } from "@ckb-ccc/core";
import { Hex } from "@ckb-ccc/core";
import { CellOutputLike } from "@ckb-ccc/core";
import { BytesLike } from "@ckb-ccc/core";
import { HexLike } from "@ckb-ccc/core";
import { OutPointLike } from "@ckb-ccc/core";
import { numToHex } from "@ckb-ccc/core";
import { ClientBlockHeader } from "@ckb-ccc/core";
import { ScriptLike } from "@ckb-ccc/core";
import { JsonRpcBlockHeader, JsonRpcCellOutput, JsonRpcOutPoint, JsonRpcScript, JsonRpcTransaction, JsonRpcTransformers } from "@ckb-ccc/core/advancedBarrel";
import { Num, Transaction } from "@ckb-ccc/core/barrel";

interface WorkerInitializeOptions {
    inputBuffer: SharedArrayBuffer;
    outputBuffer: SharedArrayBuffer;
    logLevel: string;
}
interface DbWorkerInitializeOptions extends WorkerInitializeOptions {
}

interface LightClientWorkerInitializeOptions extends WorkerInitializeOptions {
    networkFlag: NetworkSetting;
    networkSecretKey: Uint8Array
};

interface LightClientFunctionCall {
    name: string;
    args: any[];
};

type FetchResponse<T> =
    { status: "fetched"; data: T; } |
    { status: "fetching"; first_sent: bigint; } |
    { status: "added"; timestamp: bigint; } |
    { status: "not_found" };

export function transformFetchResponse<A, B>(input: FetchResponse<A>, fn: (arg: A) => B): FetchResponse<B> {
    if (input.status === "fetched") {
        return { status: "fetched", data: fn(input.data) };
    }
    return input;
}

type JsonRpcScriptType = "lock" | "type";

interface LightClientScriptStatus {
    script: JsonRpcScript;
    script_type: JsonRpcScriptType;
    block_number: Hex;
}

interface ScriptStatus {
    script: ScriptLike,
    scriptType: JsonRpcScriptType,
    blockNumber: Num
}

export function scriptStatusTo(input: LightClientScriptStatus): ScriptStatus {
    return ({
        blockNumber: numFrom(input.block_number),
        script: JsonRpcTransformers.scriptTo(input.script),
        scriptType: input.script_type
    })
}

export function scriptStatusFrom(input: ScriptStatus): LightClientScriptStatus {
    return ({
        block_number: numToHex(input.blockNumber),
        script: JsonRpcTransformers.scriptFrom(input.script),
        script_type: input.scriptType
    })
}

interface NodeAddress {
    address: string;
    score: Num;
}

interface RemoteNodeProtocol {
    id: Num;
    version: string;
}

interface LightClientPeerSyncState {
    requested_best_known_header?: JsonRpcBlockHeader;
    proved_best_known_header?: JsonRpcBlockHeader;
}

interface PeerSyncState {
    requestedBestKnownHeader?: ClientBlockHeader;
    provedBestKnownHeader?: ClientBlockHeader;
}

export function peerSyncStateTo(input: LightClientPeerSyncState): PeerSyncState {
    return {
        requestedBestKnownHeader: input.requested_best_known_header && JsonRpcTransformers.blockHeaderTo(input.requested_best_known_header),
        provedBestKnownHeader: input.proved_best_known_header && JsonRpcTransformers.blockHeaderTo(input.proved_best_known_header),
    };
}

interface LightClientRemoteNode {
    version: string;
    node_id: string;
    addresses: NodeAddress[];
    connected_duration: HexLike;
    sync_state?: LightClientPeerSyncState;
    protocols: RemoteNodeProtocol[];

}

interface RemoteNode {
    version: string;
    nodeId: string;
    addresses: NodeAddress[];
    connestedDuration: Num;
    syncState?: PeerSyncState;
    protocols: RemoteNodeProtocol[];
}

export function remoteNodeTo(input: LightClientRemoteNode): RemoteNode {
    return ({
        addresses: input.addresses,
        connestedDuration: numFrom(input.connected_duration),
        nodeId: input.node_id,
        protocols: input.protocols,
        version: input.version,
        syncState: input.sync_state && peerSyncStateTo(input.sync_state)
    })
}

interface LightClientLocalNodeProtocol {
    id: Num;
    name: string;
    support_version: string[];
}


interface LocalNodeProtocol {
    id: Num;
    name: string;
    supportVersion: string[];
}

export function localNodeProtocolTo(input: LightClientLocalNodeProtocol): LocalNodeProtocol {
    return ({
        id: input.id,
        name: input.name,
        supportVersion: input.support_version
    })
}

interface LightClientLocalNode {
    version: string;
    node_id: string;
    active: boolean;
    addresses: NodeAddress[];
    protocols: LightClientLocalNodeProtocol[];
    connections: Num;
}

interface LocalNode {
    version: string;
    nodeId: string;
    active: boolean;
    addresses: NodeAddress[];
    protocols: LocalNodeProtocol[];
    connections: bigint;
}

export function localNodeTo(input: LightClientLocalNode): LocalNode {
    return ({
        nodeId: input.node_id,
        protocols: input.protocols.map(x => localNodeProtocolTo(x)),
        active: input.active,
        addresses: input.addresses,
        connections: input.connections,
        version: input.version
    })
}
type NetworkSetting = { type: "MainNet"; config?: string; } | { type: "TestNet"; config?: string; } | { type: "DevNet"; spec: string; config: string; };
export enum LightClientSetScriptsCommand {
    All = 0,
    Partial = 1,
    Delete = 2,
}
export enum LightClientOrder {
    Desc = 0,
    Asc = 1,
}

export function cccOrderToLightClientWasmOrder(input: "asc" | "desc"): LightClientOrder {
    if (input === "asc") return LightClientOrder.Asc;
    else return LightClientOrder.Desc;
}

type LightClientCellType = "input" | "output";

interface LightClientTxWithCell {
    transaction: JsonRpcTransaction;
    block_number: Hex;
    tx_index: number;
    io_index: number;
    io_type: LightClientCellType;
}

interface LightClientTxWithCells {
    transaction: JsonRpcTransaction;
    block_number: Hex;
    tx_index: number;
    cells: Array<[LightClientCellType, number]>;
}

interface TxWithCell {
    transaction: Transaction;
    blockNumber: Num;
    txIndex: Num;
    ioIndex: Num;
    ioType: LightClientCellType;
}
interface TxWithCells {
    transaction: Transaction;
    blockNumber: Num;
    txIndex: Num;
    cells: Array<[LightClientCellType, number]>
}

interface LightClientPagination<T> {
    objects: T[];
    last_cursor: string;

}

interface GetTransactionsResponse<T> {
    transactions: T[];
    lastCursor: string;
}

export function lightClientGetTransactionsResultTo(input: LightClientPagination<LightClientTxWithCell> | LightClientPagination<LightClientTxWithCells>): GetTransactionsResponse<TxWithCell> | GetTransactionsResponse<TxWithCells> {
    if (input.objects.length === 0) {
        return ({
            lastCursor: input.last_cursor,
            transactions: []
        })
    }
    if ("io_index" in input.objects[0]) {
        return ({
            lastCursor: input.last_cursor,
            transactions: (input as LightClientPagination<LightClientTxWithCell>).objects.map((item) => ({
                transaction: JsonRpcTransformers.transactionTo(item.transaction),
                blockNumber: numFrom(item.block_number),
                txIndex: numFrom(item.tx_index),
                ioIndex: numFrom(item.io_index),
                ioType: item.io_type
            }))
        }) as GetTransactionsResponse<TxWithCell>
    } else {
        return ({
            lastCursor: input.last_cursor,
            transactions: (input as LightClientPagination<LightClientTxWithCells>).objects.map((item) => ({
                transaction: JsonRpcTransformers.transactionTo(item.transaction),
                blockNumber: numFrom(item.block_number),
                txIndex: numFrom(item.tx_index),
                cells: item.cells
            }))
        }) as GetTransactionsResponse<TxWithCells>
    }
}

interface LightClientGetCellsResponse {
    last_cursor: string;
    objects: {
        out_point: JsonRpcOutPoint;
        output: JsonRpcCellOutput;
        output_data?: Hex;
        block_number: Hex;
        tx_index: Hex;
    }[];
}


interface CellWithBlockNumAndTxIndex {
    outPoint: OutPointLike;
    cellOutput: CellOutputLike;
    outputData: BytesLike;
    blockNumber: Num;
    txIndex: Num;
};

interface GetCellsResponse {
    lastCursor: string;
    cells: CellWithBlockNumAndTxIndex[];
}



export function getCellsResponseFrom(input: LightClientGetCellsResponse): GetCellsResponse {
    return {
        lastCursor: input.last_cursor,
        cells: input.objects.map(item => ({
            outPoint: JsonRpcTransformers.outPointTo(item.out_point),
            cellOutput: JsonRpcTransformers.cellOutputTo(item.output),
            outputData: item.output_data ?? "0x",
            blockNumber: numFrom(item.block_number),
            txIndex: numFrom(item.tx_index)
        }))
    }
}

type TraceRecord = {
    type: "DownloadBlock";
    start_at: number;
    count: number;
    matched_count: number;

} | {
    type: "FinalizeCheckPoints";
    count: number;
    stop_at: number;
};

export {
    LightClientFunctionCall,
    WorkerInitializeOptions,
    DbWorkerInitializeOptions,
    LightClientWorkerInitializeOptions,
    FetchResponse,
    LightClientScriptStatus,
    ScriptStatus,
    LightClientRemoteNode,
    RemoteNode,
    LocalNode,
    LightClientLocalNode,
    NetworkSetting,
    LightClientTxWithCell,
    LightClientTxWithCells,
    TxWithCell,
    TxWithCells,
    GetTransactionsResponse,
    CellWithBlockNumAndTxIndex,
    GetCellsResponse,
    TraceRecord,
    Num,
    Transaction
}
