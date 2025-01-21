import { ClientIndexerSearchKeyLike, ClientIndexerSearchKeyTransactionLike, ClientTransactionResponse } from "@ckb-ccc/core";
import { FetchResponse, LocalNode, localNodeTo, RemoteNode, remoteNodeTo, ScriptStatus, scriptStatusFrom, scriptStatusTo, LightClientSetScriptsCommand, transformFetchResponse, cccOrderToLightClientWasmOrder, GetTransactionsResponse, TxWithCell, TxWithCells, lightClientGetTransactionsResultTo, LightClientLocalNode, LightClientRemoteNode, LightClientScriptStatus, NetworkSetting, GetCellsResponse, getCellsResponseFrom, LightClientWorkerInitializeOptions, TraceRecord } from "./types.ts";
import { ClientBlock, ClientBlockHeader, Hex, hexFrom, HexLike, Num, numFrom, NumLike, numToHex, TransactionLike } from "@ckb-ccc/core/barrel";
import { JsonRpcBlockHeader, JsonRpcTransformers } from "@ckb-ccc/core/advancedBarrel";
import { Mutex } from "async-mutex";
import { bytesFrom } from "@ckb-ccc/core";

import DbWorker from "./db.worker.ts";
import LightClientWorker from "./lightclient.worker.ts";

const DEFAULT_BUFFER_SIZE = 50 * (1 << 20);
/**
 * A LightClient instance
 */
class LightClient {
    private dbWorker: Worker | null
    private lightClientWorker: Worker | null
    private inputBuffer: SharedArrayBuffer
    private outputBuffer: SharedArrayBuffer
    private commandInvokeLock: Mutex
    private traceLogBuffer: SharedArrayBuffer
    private stopping: boolean = false;
    private traceLogCallback: (value: TraceRecord) => void | null = null;
    /**
     * Construct a LightClient instance.
     * inputBuffer and outputBuffer are buffers used for transporting data between database and light client. Set them to appropriate sizes.
     * @param inputBufferSize Size of inputBuffer
     * @param outputBufferSize Size of outputBuffer
     */
    constructor(inputBufferSize = DEFAULT_BUFFER_SIZE, outputBufferSize = DEFAULT_BUFFER_SIZE) {
        // this.dbWorker = new Worker(new URL("./db.worker.ts?inline", import.meta.url), { type: "module" });
        // this.lightClientWorker = new Worker(new URL("./lightclient.worker.ts?inline", import.meta.url), { type: "module" });
        this.dbWorker = new DbWorker();
        this.lightClientWorker = new LightClientWorker();
        this.inputBuffer = new SharedArrayBuffer(inputBufferSize);
        this.outputBuffer = new SharedArrayBuffer(outputBufferSize);
        this.traceLogBuffer = new SharedArrayBuffer(10 * 1024);
        this.commandInvokeLock = new Mutex();
    }
    /**
     * Set a callback to receive trace log records
     * @param cb The callback
     */
    setTraceLogCallback(cb: (value: TraceRecord) => void) {
        this.traceLogCallback = cb;
    }

    /**
     * Start the light client.
     * @param networkSetting Network setting for light-client-wasm. You can specify config if you are using mainnet or testnet. You must provide config and spec if you are using devnet.
     * @param logLevel Log Level for light-client-db-worker and light-client-wasm
     */
    async start(networkSetting: NetworkSetting, networkSecretKey: Hex, logLevel: "trace" | "debug" | "info" | "error" = "info") {
        this.dbWorker.postMessage({
            inputBuffer: this.inputBuffer,
            outputBuffer: this.outputBuffer,
            logLevel: logLevel
        });
        this.lightClientWorker.postMessage({
            inputBuffer: this.inputBuffer,
            outputBuffer: this.outputBuffer,
            networkFlag: networkSetting,
            logLevel: logLevel,
            traceLogBuffer: this.traceLogBuffer,
            networkSecretKey: bytesFrom(networkSecretKey)
        } as LightClientWorkerInitializeOptions);
        await new Promise<void>((res, rej) => {
            this.dbWorker.onmessage = () => res();
            this.dbWorker.onerror = (evt) => rej(evt);
        });
        await new Promise<void>((res, rej) => {
            this.lightClientWorker.onmessage = () => res();
            this.lightClientWorker.onerror = (evt) => rej(evt);
        });
        (async () => {
            while (!this.stopping) {
                const i32arr = new Int32Array(this.traceLogBuffer);
                const u8arr = new Uint8Array(this.traceLogBuffer);
                const resp = Atomics.waitAsync(i32arr, 0, 0);
                if (resp.async) {
                    await resp.value;
                }
                if (i32arr[0] === 1) {
                    const length = i32arr[1];
                    const data = u8arr.slice(8, 8 + length);
                    const decoded = JSON.parse(new TextDecoder().decode(data));
                    if (this.traceLogCallback !== null) this.traceLogCallback(decoded);
                    i32arr[0] = 0;
                    Atomics.notify(i32arr, 0);
                }
            }
            console.log("Exiting trace log fetcher..");
        })();
    }
    private invokeLightClientCommand(name: string, args?: any[]): Promise<any> {
        // Why use lock here?
        // light-client-wasm provides synchronous APIs, means if we send a call request through postMessage, onmessage will be called only when the command call resolved. 
        // We use lock here to avoid multiple call to postMessage before onmessage fired, to avoid mixed result of different calls 
        // Since light-client-wasm is synchronous, we won't lose any performance by locking here
        return this.commandInvokeLock.runExclusive(async () => {
            this.lightClientWorker.postMessage({
                name,
                args: args || []
            });
            return await new Promise((resolve, reject) => {
                const clean = () => {
                    this.lightClientWorker.removeEventListener("message", resolveFn);
                    this.lightClientWorker.removeEventListener("error", errorFn);
                }
                const resolveFn = (evt: MessageEvent<{ ok: true; data: any } | { ok: false; error: string; }>) => {
                    if (evt.data.ok === true) {
                        resolve(evt.data.data);
                    } else {
                        reject(evt.data.error);
                    }
                    clean();

                };
                const errorFn = (evt: ErrorEvent) => {
                    reject(evt);
                    clean();

                };
                this.lightClientWorker.addEventListener("message", resolveFn);
                this.lightClientWorker.addEventListener("error", errorFn);
            })
        })

    }
    /**
     * Stop the light client instance.
     */
    async stop() {
        // await this.invokeLightClientCommand("stop");
        this.dbWorker.terminate();
        this.lightClientWorker.terminate();
        this.stopping = true;
    }
    /**
     * Returns the header with the highest block number in the canonical chain
     * @returns HeaderView
     */
    async getTipHeader(): Promise<ClientBlockHeader> {
        return JsonRpcTransformers.blockHeaderTo(await this.invokeLightClientCommand("get_tip_header"));
    }
    /**
     * Returns the genesis block
     * @returns BlockView
     */
    async getGenesisBlock(): Promise<ClientBlock> {
        return JsonRpcTransformers.blockTo(await this.invokeLightClientCommand("get_genesis_block"));
    }
    /**
     * Returns the information about a block header by hash.
     * @param hash the block hash, equal to Vec<u8> in Rust
     * @returns HeaderView
     */
    async getHeader(hash: HexLike): Promise<ClientBlockHeader | undefined> {
        const resp = await this.invokeLightClientCommand("get_header", [hexFrom(hash)]);
        return resp ? JsonRpcTransformers.blockHeaderTo(resp) : resp;
    }
    /**
     * Fetch a header from remote node. If return status is not_found will re-sent fetching request immediately.
     * @param hash the block hash, equal to Vec<u8> in Rust
     * @returns FetchHeaderResponse
     */
    async fetchHeader(hash: HexLike): Promise<FetchResponse<ClientBlockHeader>> {
        return transformFetchResponse(await this.invokeLightClientCommand("fetch_header", [hexFrom(hash)]), (arg: JsonRpcBlockHeader) => JsonRpcTransformers.blockHeaderTo(arg));
    }
    /**
     * See https://github.com/nervosnetwork/ckb/tree/develop/rpc#method-estimate_cycles
     * @param tx The transaction
     * @returns Estimate cycles
     */
    async estimateCycles(tx: TransactionLike): Promise<Num> {
        return numFrom((await this.invokeLightClientCommand("estimate_cycles", [JsonRpcTransformers.transactionFrom(tx)]) as { cycles: Hex }).cycles);
    }
    /**
     * Returns the local node information.
     * @returns LocalNode
     */
    async localNodeInfo(): Promise<LocalNode> {
        return localNodeTo(await this.invokeLightClientCommand("local_node_info") as LightClientLocalNode);
    }
    /**
     * Returns the connected peers' information.
     * @returns 
     */
    async getPeers(): Promise<RemoteNode[]> {
        return (await this.invokeLightClientCommand("get_peers") as LightClientRemoteNode[]).map(x => remoteNodeTo(x));
    }
    /**
     * Set some scripts to filter
     * @param scripts Array of script status
     * @param command An optional enum parameter to control the behavior of set_scripts
     */
    async setScripts(scripts: ScriptStatus[], command?: LightClientSetScriptsCommand): Promise<void> {
        await this.invokeLightClientCommand("set_scripts", [scripts.map(x => scriptStatusFrom(x)), command]);
    }
    /**
     * Get filter scripts status
     */
    async getScripts(): Promise<ScriptStatus[]> {
        return (await this.invokeLightClientCommand("get_scripts") as LightClientScriptStatus[]).map(x => scriptStatusTo(x));
    }
    /**
     * See https://github.com/nervosnetwork/ckb-indexer#get_cells
     * @param searchKey 
     * @param order 
     * @param limit 
     * @param afterCursor 
     */
    async getCells(
        searchKey: ClientIndexerSearchKeyLike,
        order?: "asc" | "desc",
        limit?: NumLike,
        afterCursor?: Hex
    ): Promise<GetCellsResponse> {
        const resp = await this.invokeLightClientCommand("get_cells", [
            JsonRpcTransformers.indexerSearchKeyFrom(searchKey),
            cccOrderToLightClientWasmOrder(order ?? "asc"),
            Number(numFrom(numToHex(limit ?? 10))),
            afterCursor ? bytesFrom(afterCursor) : afterCursor
        ]);
        return getCellsResponseFrom(resp);
    }
    /**
     * See https://github.com/nervosnetwork/ckb-indexer#get_transactions
     * @param searchKey 
     * @param order 
     * @param limit 
     * @param afterCursor 
     * @returns 
     */
    async getTransactions(
        searchKey: ClientIndexerSearchKeyTransactionLike,
        order?: "asc" | "desc",
        limit?: NumLike,
        afterCursor?: Hex
    ): Promise<GetTransactionsResponse<TxWithCell> | GetTransactionsResponse<TxWithCells>> {
        return lightClientGetTransactionsResultTo(await this.invokeLightClientCommand(
            "get_transactions",
            [
                JsonRpcTransformers.indexerSearchKeyTransactionFrom(searchKey),
                cccOrderToLightClientWasmOrder(order ?? "asc"),
                Number(numFrom(numToHex(limit ?? 10))),
                afterCursor ? bytesFrom(afterCursor) : afterCursor
            ]
        ));
    }
    /**
     * See https://github.com/nervosnetwork/ckb-indexer#get_cells_capacity
     * @param searchKey 
     * @returns 
     */
    async getCellsCapacity(searchKey: ClientIndexerSearchKeyLike): Promise<Num> {
        return numFrom(((await this.invokeLightClientCommand("get_cells_capacity", [JsonRpcTransformers.indexerSearchKeyFrom(searchKey)])) as any).capacity);
    }
    /**
     * Submits a new transaction and broadcast it to network peers
     * @param tx Transaction
     * @returns H256
     */
    async sendTransaction(tx: TransactionLike): Promise<Hex> {
        return hexFrom(await this.invokeLightClientCommand("send_transaction", [JsonRpcTransformers.transactionFrom(tx)]));
    }
    /**
     * Returns the information about a transaction by hash, the block header is also returned.
     * @param txHash the transaction hash
     * @returns 
     */
    async getTransaction(txHash: HexLike): Promise<ClientTransactionResponse | undefined> {
        return JsonRpcTransformers.transactionResponseTo(await this.invokeLightClientCommand("get_transaction", [hexFrom(txHash)]));
    }
    /**
     * Fetch a transaction from remote node. If return status is not_found will re-sent fetching request immediately.
     * @param txHash the transaction hash
     * @returns 
     */
    async fetchTransaction(txHash: HexLike): Promise<FetchResponse<ClientTransactionResponse>> {
        return transformFetchResponse<any, ClientTransactionResponse>(await this.invokeLightClientCommand("fetch_transaction", [hexFrom(txHash)]), JsonRpcTransformers.transactionResponseTo);
    }

}

export { LightClient };

/**
 * Generate a random network secret key.
 * @returns The secret key.
 */
export function randomSecretKey(): Hex {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    return hexFrom(arr);
}

export * from "./types.ts";
