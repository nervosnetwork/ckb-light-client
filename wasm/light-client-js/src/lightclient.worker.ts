import { LightClientFunctionCall, LightClientWorkerInitializeOptions } from "./types";
import wasmModule from "ckb-light-client-wasm";
onerror = err => {
    console.error(err);
}
let loaded = false;
onmessage = async (evt) => {
    if (!loaded) {
        const data = evt.data as LightClientWorkerInitializeOptions;
        wasmModule.set_shared_array(data.inputBuffer, data.outputBuffer);
        await wasmModule.light_client(data.networkFlag, data.logLevel, data.networkSecretKey);
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
};

export default {} as typeof Worker & { new(): Worker };
