// Public API regression: real WASM workers and IndexedDB, without peers.
import { LightClient, LightClientSetScriptsCommand } from '/runtime.js';

const A = '0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f';
const B = '0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37';
const GENESIS = '0x10639e0895502b5688a6be8cf69460d76541bfa4821629d86d62ba0aae3f9606';
const point = p => `${p.txHash}:${BigInt(p.index)}`;
const scriptKey = s => `${s.codeHash}:${s.hashType}:${s.args}`;
const results = { startedAt: new Date().toISOString(), package: 'local source build',
  crossOriginIsolated, sharedArrayBuffer: typeof SharedArrayBuffer, atomicsWaitAsync: typeof Atomics.waitAsync,
  assertions: [] };
globalThis.repro = { done: false, results };
const require = (condition, message) => { if (!condition) throw new Error(message); };
const database = `ckb-batch-repro-${crypto.randomUUID()}`;
const config = `chain = "testnet"
[store]
path = "${database}"
[network]
path = "${database}-network"
listen_addresses = []
bootnodes = []
max_peers = 4
max_outbound_peers = 2
ping_interval_secs = 120
ping_timeout_secs = 1200
connect_outbound_interval_secs = 3600
upnp = false
discovery_local_address = false
bootnode_mode = false
[rpc]
listen_address = "127.0.0.1:0"
`;
let client;
async function open() {
  // Assign first so a failed startup still gets cleaned up by finally.
  client = new LightClient();
  // Public deterministic test-only transport identity; never use for a wallet.
  await client.start({ type: 'TestNet', config }, `0x${'01'.repeat(32)}`, 'error', 'wss');
}
async function read(scripts) {
  const cells = [];
  let capacity = 0n;
  const history = new Set();
  for (const script of scripts) {
    const key = { script, scriptType: 'lock', withData: false };
    const page = await client.getCells(key, 'asc', 100);
    require(page.cells.length < 100, 'Unexpected fixture pagination; refusing a partial result');
    // 0.5.5 search semantics are a subset of CCC. Check every returned lock.
    require(page.cells.every(c => scriptKey(c.cellOutput.lock) === scriptKey(script)), 'Unexpected prefix-match result');
    cells.push(...page.cells.map(c => ({ outPoint: point(c.outPoint), capacity: String(c.cellOutput.capacity) })));
    capacity += await client.getCellsCapacity(key);
    const txs = await client.getTransactions({ ...key, groupByTransaction: true }, 'asc', 100);
    require(txs.transactions.length < 100, 'Unexpected fixture history pagination');
    for (const tx of txs.transactions) history.add(tx.transaction.hash());
  }
  require(cells.reduce((sum,c) => sum + BigInt(c.capacity),0n) === capacity, 'Capacity query disagrees with returned cell values');
  const peers = await client.getPeers();
  require(peers.length === 0, 'Unexpected connected peers');
  return { cells: cells.sort((a,b) => a.outPoint.localeCompare(b.outPoint)), capacity: String(capacity), history: [...history].sort(), peers };
}
try {
  require(crossOriginIsolated, 'COOP/COEP isolation missing');
  results.stage = 'initial runtime startup';
  await open();
  results.stage = 'genesis filtering and queries';
  const genesis = await client.getGenesisBlock();
  require(genesis.header.hash === GENESIS, 'Unexpected TestNet genesis');
  const creator = genesis.transactions.find(t => t.hash() === A);
  const spender = genesis.transactions.find(t => t.hash() === B);
  require(creator && spender && genesis.transactions.indexOf(creator) < genesis.transactions.indexOf(spender), 'Fixture transactions/order changed');
  require(spender.inputs.some(input => point(input.previousOutput) === `${A}:5`), 'B does not consume A:5');
  const scripts = [...new Map([creator.outputs[5].lock, ...spender.outputs.map(o => o.lock)].map(s => [scriptKey(s), s])).values()];
  const watched = new Set(scripts.map(scriptKey));
  const expected = new Map();
  // Oracle only: the runtime itself performs all filtering and persistence.
  for (const tx of genesis.transactions) {
    for (const input of tx.inputs) expected.delete(point(input.previousOutput));
    tx.outputs.forEach((output,index) => { if (watched.has(scriptKey(output.lock))) expected.set(`${tx.hash()}:${index}`, BigInt(output.capacity)); });
  }
  const expectedCapacity = [...expected.values()].reduce((sum,c) => sum+c,0n);
  require(expected.size === 7 && expectedCapacity === 126490100000000n, 'Fixture oracle changed');
  results.fixture = { genesis: GENESIS, creator: A, spender: B, spentOutPoint: `${A}:5`,
    watchedScripts: scripts.map(s => ({ codeHash:s.codeHash, hashType:s.hashType, args:s.args, role:'lock', boundary:0 })),
    expectedCells: [...expected.keys()].sort(), expectedCapacity: String(expectedCapacity) };
  await client.setScripts(scripts.map(script => ({ script, scriptType:'lock', blockNumber:0n })), LightClientSetScriptsCommand.All);
  results.initial = await read(scripts);
  await client.stop();
  client = null;
  results.stage = 'runtime restart and queries';
  await open();
  results.reopened = await read(scripts);
  for (const phase of ['initial','reopened']) {
    const observed = results[phase];
    require(observed.history.includes(A) && observed.history.includes(B), `${phase}: grouped history missing A/B`);
    const keys = observed.cells.map(c => c.outPoint).sort();
    results.assertions.push(
      { name:`${phase}: exact live set`, passed:JSON.stringify(keys) === JSON.stringify([...expected.keys()].sort()), expected:7, actual:keys.length },
      { name:`${phase}: spent A:5 absent`, passed:!keys.includes(`${A}:5`), expected:false, actual:keys.includes(`${A}:5`) },
      { name:`${phase}: indexed capacity`, passed:observed.capacity === String(expectedCapacity), expected:String(expectedCapacity), actual:observed.capacity }
    );
    observed.extraCells = keys.filter(k => !expected.has(k));
    observed.missingCells = [...expected.keys()].filter(k => !keys.includes(k));
    observed.excessShannons = String(BigInt(observed.capacity) - expectedCapacity);
  }
  results.persistence = JSON.stringify(results.initial.cells) === JSON.stringify(results.reopened.cells) && results.initial.capacity === results.reopened.capacity;
  results.assertions.push({ name:'state persists after worker restart', passed:results.persistence });

  // Nonzero cursors isolate metadata batches from genesis filtering.
  results.stage = 'script batch controls';
  const [first, second] = scripts;
  const status = (script, height) => ({ script, scriptType:'lock', blockNumber:BigInt(height) });
  const normalize = entries => entries.map(s => [scriptKey(s.script), String(s.blockNumber)]).sort();
  async function checkScripts(name, entries, command, expected) {
    await client.setScripts(entries, command);
    const actual = normalize(await client.getScripts());
    const wanted = normalize(expected);
    results.assertions.push({ name, passed:JSON.stringify(actual) === JSON.stringify(wanted), expected:wanted, actual });
  }
  await checkScripts('delete then put: script replacement', [status(first,13), status(second,14)],
    LightClientSetScriptsCommand.All, [status(first,13), status(second,14)]);
  await checkScripts('repeated puts: final cursor wins', [status(first,21), status(first,22)],
    LightClientSetScriptsCommand.Partial, [status(first,22), status(second,14)]);
  await checkScripts('interleaved script updates', [status(first,31), status(second,41), status(first,32), status(second,42)],
    LightClientSetScriptsCommand.Partial, [status(first,32), status(second,42)]);
  await checkScripts('delete selected script', [status(first,32)],
    LightClientSetScriptsCommand.Delete, [status(second,42)]);
  await client.stop();
  client = null;
  results.stage = 'script controls restart';
  await open();
  const actual = normalize(await client.getScripts());
  results.assertions.push({ name:'script controls persist after worker restart',
    passed:JSON.stringify(actual) === JSON.stringify(normalize([status(second,42)])), actual });
  results.outcome = results.assertions.every(a => a.passed) ? 'INVARIANTS_PASS' : 'REGRESSION_FAILED';
  results.stage = 'complete';
} catch (error) { results.outcome = 'EXECUTION_ERROR'; results.error = String(error); }
finally {
  if (client) { try { await client.stop(); } catch (error) { results.cleanupError = String(error); } }
  results.finishedAt = new Date().toISOString();
  document.querySelector('#result').textContent = JSON.stringify(results,null,2);
  globalThis.repro.done = true;
}
