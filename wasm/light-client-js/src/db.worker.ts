import { DbWorkerInitializeOptions } from "./types";
import wasmModule from "ckb-light-client-db-worker";
import { parentPort as self } from "worker_threads";
// onerror = event => {
//     console.error(event);
// }

self.on("message", async (evt) => {
    const data = evt as DbWorkerInitializeOptions;
    wasmModule.set_shared_array(data.inputBuffer, data.outputBuffer);
    self.postMessage({});
    await wasmModule.main_loop(data.logLevel);
});

export default {} as typeof Worker & { new(): Worker };
