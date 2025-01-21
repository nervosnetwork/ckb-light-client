# ckb-light-client-wasm

## Build

Run the following commands at the project root:
```
cargo install wasm-pack
npm install
npm run build -ws
```

Requirements:
- cargo
- clang

Build results will be at `wasm/light-client-js/dist`, a js file ready to be bundled by webpack, or directly used in browser.

## Use
```
npm install ckb-light-client-js
```
