import * as wasmModule from "./pkg/light-client-wasm";
import wasm from "./pkg/light-client-wasm_bg.wasm";
wasmModule.initSync({ module: wasm });

export default wasmModule;
