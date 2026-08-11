package com.nervosnetwork.ckblightclient

/**
 * JNI bridge to CKB Light Client native library
 *
 * This object provides access to the native Rust implementation of CKB Light Client.
 * The library is loaded from libckb_light_client_lib.so at initialization.
 */
object LightClientNative {
    init {
        System.loadLibrary("ckb_light_client_lib")
    }

    // ========================================
    // Lifecycle Management
    // ========================================

    /**
     * Initialize the light client
     *
     * @param configPath Absolute path to TOML config file
     * @param statusCallback Callback for status changes
     * @return true if initialization succeeded, false otherwise
     */
    external fun nativeInit(
        configPath: String,
        statusCallback: StatusCallback
    ): Boolean

    /**
     * Start the light client
     *
     * Transitions from INIT to RUNNING state.
     * Must call nativeInit() first.
     *
     * @return true if start succeeded, false otherwise
     */
    external fun nativeStart(): Boolean

    /**
     * Stop the light client
     *
     * Gracefully shuts down the light client.
     * Broadcasts exit signals and waits for services to stop.
     *
     * @return true if stop succeeded, false otherwise
     */
    external fun nativeStop(): Boolean

    /**
     * Get current status
     *
     * @return Status code: STATUS_INIT (0), STATUS_RUNNING (1), or STATUS_STOPPED (2)
     */
    external fun nativeGetStatus(): Int

    // ========================================
    // Query APIs (17 functions)
    // ========================================

    /**
     * Get tip header
     * @return JSON string of HeaderView, or null on error
     */
    external fun nativeGetTipHeader(): String?

    /**
     * Get genesis block
     * @return JSON string of BlockView, or null on error
     */
    external fun nativeGetGenesisBlock(): String?

    /**
     * Get header by hash
     * @param hash Block hash (hex string with 0x prefix)
     * @return JSON string of HeaderView, or null if not found
     */
    external fun nativeGetHeader(hash: String): String?

    /**
     * Fetch header (with fetch status)
     * @param hash Block hash (hex string with 0x prefix)
     * @return JSON string of FetchStatus<HeaderView>, or null on error
     */
    external fun nativeFetchHeader(hash: String): String?

    /**
     * Set filter scripts
     * @param scriptsJson JSON array of ScriptStatus
     * @param command Command type: 0=All, 1=Partial, 2=Delete
     * @return true if succeeded, false otherwise
     */
    external fun nativeSetScripts(scriptsJson: String, command: Int): Boolean

    /**
     * Get filter scripts
     * @return JSON array of ScriptStatus, or null on error
     */
    external fun nativeGetScripts(): String?

    /**
     * Get cells
     * @param searchKeyJson JSON of SearchKey
     * @param order "asc" or "desc"
     * @param limit Maximum number of results
     * @param cursor Pagination cursor (JSON), or null for first page
     * @return JSON of Pagination<Cell>, or null on error
     */
    external fun nativeGetCells(
        searchKeyJson: String,
        order: String,
        limit: Int,
        cursor: String?
    ): String?

    /**
     * Get transactions
     * @param searchKeyJson JSON of SearchKey
     * @param order "asc" or "desc"
     * @param limit Maximum number of results
     * @param cursor Pagination cursor (JSON), or null for first page
     * @return JSON of Pagination<Tx>, or null on error
     */
    external fun nativeGetTransactions(
        searchKeyJson: String,
        order: String,
        limit: Int,
        cursor: String?
    ): String?

    /**
     * Get cells capacity
     * @param searchKeyJson JSON of SearchKey
     * @return JSON of CellsCapacity, or null on error
     */
    external fun nativeGetCellsCapacity(searchKeyJson: String): String?

    /**
     * Send transaction
     * @param txJson JSON of Transaction
     * @return Transaction hash (hex string), or null on error
     */
    external fun nativeSendTransaction(txJson: String): String?

    /**
     * Get transaction
     * @param hash Transaction hash (hex string with 0x prefix)
     * @return JSON of TransactionWithStatus, or null if not found
     */
    external fun nativeGetTransaction(hash: String): String?

    /**
     * Fetch transaction (with fetch status)
     * @param hash Transaction hash (hex string with 0x prefix)
     * @return JSON of FetchStatus<TransactionWithStatus>, or null on error
     */
    external fun nativeFetchTransaction(hash: String): String?

    /**
     * Get local node info
     * @return JSON of LocalNode, or null on error
     */
    external fun nativeLocalNodeInfo(): String?

    /**
     * Get peers
     * @return JSON array of RemoteNode, or null on error
     */
    external fun nativeGetPeers(): String?

    /**
     * Estimate transaction cycles
     * @param txJson JSON of Transaction
     * @return JSON of EstimateCycles, or null on error
     */
    external fun nativeEstimateCycles(txJson: String): String?

    /**
     * Call RPC method
     *
     * Generic RPC interface that supports common methods:
     * - get_peers
     * - get_tip_header
     * - get_genesis_block
     * - get_scripts
     *
     * @param method RPC method name
     * @return JSON-RPC 2.0 formatted response as string, or null on error
     */
    external fun callRpc(method: String): String?

    // ========================================
    // Callback Interfaces
    // ========================================

    /**
     * Status callback interface
     *
     * Receives status change notifications.
     * Called from native thread, so must be thread-safe.
     */
    interface StatusCallback {
        /**
         * Called when status changes
         *
         * @param status Status name ("initialized", "running", "stopped", etc.)
         * @param data Additional data (usually empty)
         */
        fun onStatusChange(status: String, data: String)
    }

    // ========================================
    // Constants
    // ========================================

    /** Status: Initialized but not started */
    const val STATUS_INIT = 0

    /** Status: Running */
    const val STATUS_RUNNING = 1

    /** Status: Stopped */
    const val STATUS_STOPPED = 2

    /** SetScripts command: Replace all scripts */
    const val CMD_SET_SCRIPTS_ALL = 0

    /** SetScripts command: Partial update */
    const val CMD_SET_SCRIPTS_PARTIAL = 1

    /** SetScripts command: Delete scripts */
    const val CMD_SET_SCRIPTS_DELETE = 2
}
