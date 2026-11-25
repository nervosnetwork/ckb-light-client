import * as wasmModule from "./pkg/light-client-wasm.js";
import wasm from "./pkg/light-client-wasm_bg.wasm";
import "fake-indexeddb/auto"



globalThis.indexedDB = indexedDB;

wasmModule.initSync({ module: wasm });

export default wasmModule;
