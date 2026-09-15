import * as wasmModule from "./pkg/light-client-db-worker.js";
import wasm from "./pkg/light-client-db-worker_bg.wasm"
import "fake-indexeddb/auto"
import path from "path";

import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// const indexedDB = IndexedDB.create(destructible, path.join(__dirname, 'tmp', 'readme'))
globalThis.indexedDB = indexedDB;

wasmModule.initSync({ module: wasm });

export default wasmModule;
