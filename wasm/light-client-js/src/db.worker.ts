import { DbWorkerInitializeOptions } from "./types";
import wasmModule from "ckb-light-client-db-worker";
onerror = event => {
    console.error(event);
}

onmessage = async (evt) => {
    const data = evt.data as DbWorkerInitializeOptions;
    wasmModule.set_shared_array(data.inputBuffer, data.outputBuffer);
    self.postMessage({});
    await wasmModule.main_loop(data.logLevel);
}

export default {} as typeof Worker & { new(): Worker };
