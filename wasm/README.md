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

## Browser storage tests

After building the WASM workspace, run `make test-wasm-browser` with Chrome
and a compatible ChromeDriver installed. This runs the DB worker's IndexedDB
tests and a public API regression against the local `dist/index.js` bundle.
The latter requires Node 22.14 or newer and uses isolated headless Chrome,
offline testnet genesis, and a disposable database/profile. It checks same-block
creation/spending, live cells, capacity, transaction history, script replacement,
and persistence after stopping the client and creating new workers.

The individual commands are:

```sh
wasm-pack test --headless --chrome ./wasm/light-client-db-worker/
node wasm/light-client-js/tests/browser/run.mjs --runtime wasm/light-client-js/dist/index.js
```

Set `CHROME` (or pass `--browser` to the Node runner) and `CHROMEDRIVER` if the
executables are not detected. For a custom Chrome binary in the Rust tests,
set `goog:chromeOptions.binary` in a `webdriver.json` file in
`wasm/light-client-db-worker/`. The Node runner exits nonzero on a failed assertion
or execution/cleanup error and saves `result.json` in a new `ckb-repro-*`
directory. Its disposable profile is removed automatically.

On Linux hosts without a usable Chrome sandbox, `CHROME_NO_SANDBOX=1` opts the
Node runner into `--no-sandbox`. CI enables this for the offline, locally served
test fixture; leave it unset when a sandbox is available.

The batch correction applies to future writes; it does not automatically repair
entries left by older runtimes. Existing affected stores require reindexing.

## Use
```
npm install ckb-light-client-js
```
