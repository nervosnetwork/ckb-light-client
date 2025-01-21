import * as wasmModule from "./pkg/light-client-db-worker";
import wasm from "./pkg/light-client-db-worker_bg.wasm"
wasmModule.initSync({ module: wasm });

export default wasmModule;
