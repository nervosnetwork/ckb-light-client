import { LightClientFunctionCall, LightClientWorkerInitializeOptions } from "./types";
import wasmModule from "ckb-light-client-wasm";
import { parentPort as self } from "worker_threads";
// onerror = err => {
//     console.error(err);
// }
let loaded = false;
// onmessage = ;

self.on("message", async (evt) => {
    if (!loaded) {
        const data = evt as LightClientWorkerInitializeOptions;
        wasmModule.set_shared_array(data.inputBuffer, data.outputBuffer);
        if (data.networkConfigIsJSObject) {
            data.networkFlag.config = JSON.stringify(data.networkFlag.config);
        }
        await wasmModule.light_client(
            data.networkFlag,
            data.logLevel,
            data.networkSecretKey,
            data.transportType,
            data.networkConfigIsJSObject,
        );
        self.postMessage({});
        loaded = true;
        return;
    }
    const data = evt.data as LightClientFunctionCall;
    try {
        self.postMessage({
            ok: true,
            data: ((wasmModule as any)[data.name])(...evt.data.args)
        })
    } catch (e) {
        self.postMessage({
            ok: false,
            error: `${e}`
        })
        console.error(e);
    }
});

export default {} as typeof Worker & { new(): Worker };
