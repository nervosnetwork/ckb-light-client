import * as esbuild from 'esbuild'
import inlineWorkerPlugin from './inline-worker-plugin.js';
import { polyfillNode } from "esbuild-plugin-polyfill-node";
import { dtsPlugin } from "esbuild-plugin-d.ts";
import fs from "node:fs/promises";
const tsconfig = JSON.parse(await fs.readFile("./tsconfig.json"));
const profile = process.env.PROFILE;

await esbuild.build({
    entryPoints: ["./src/index.ts"],
    bundle: true,
    outdir: "dist",
    plugins: [/*polyfillNode(),*/ inlineWorkerPlugin({
        format: "iife"
    }), /*dtsPlugin({ tsconfig })*/],
    target: [
        "esnext"
    ],
    platform: "node",
    sourcemap: true,
    format: "esm",
    globalName: "CkbLightClient",
    minify: profile === "prod",
    logLevel: "debug",
    external: [
        "ws",
        "isomorphic-ws",
        "events",
        "buffer",
        "util",
        "stream"
    ],
    banner: {
        js: "import { createRequire } from 'module'; const require = createRequire(import.meta.url);"
    }
})
