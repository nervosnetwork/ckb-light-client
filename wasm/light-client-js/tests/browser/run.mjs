// Node built-ins only. Supply the bundle built from this checkout.
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { access, readFile, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';

const options = {};
for (let i=2; i<process.argv.length; i+=2) {
  const key = process.argv[i];
  if (!['--runtime','--browser','--output'].includes(key) || !process.argv[i+1]) throw new Error('Usage: node repro/run.mjs --runtime path/to/dist/index.js [--browser path/to/chrome] [--output NEW-directory]');
  options[key.slice(2)] = process.argv[i+1];
}
if (!options.runtime) throw new Error('--runtime must point to the locally built dist/index.js');
if (typeof WebSocket !== 'function') throw new Error('Use Node 22.14 or newer with built-in WebSocket');
const bundle = await readFile(resolve(options.runtime));
const digest = createHash('sha256').update(bundle).digest('hex');
const candidates = options.browser || process.env.CHROME ? [options.browser ?? process.env.CHROME] : process.platform === 'win32' ? [
  join(process.env.ProgramFiles ?? 'C:/Program Files','Google/Chrome/Application/chrome.exe'),
  join(process.env.LOCALAPPDATA ?? 'C:/invalid','Google/Chrome/Application/chrome.exe'),
] : process.platform === 'darwin' ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'] : ['/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'];
let executable;
for (const path of candidates) { try { await access(path); executable=path; break; } catch {} }
if (!executable) throw new Error('Chrome not found; supply --browser with its executable path');
const output = resolve(options.output ?? `ckb-repro-${Date.now()}`);
await mkdir(output); // Refuse any existing output path, including old evidence.
const profile = await mkdtemp(join(output,'profile-'));
const source = dirname(fileURLToPath(import.meta.url));
const routes = new Map([
  ['/',{type:'text/html',data:await readFile(join(source,'index.html'))}],
  ['/test.mjs',{type:'text/javascript',data:await readFile(join(source,'test.mjs'))}],
  ['/runtime.js',{type:'text/javascript',data:bundle}],
]);
const headers = {
  'Cross-Origin-Opener-Policy':'same-origin','Cross-Origin-Embedder-Policy':'require-corp',
  'Content-Security-Policy':"default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; connect-src 'self'; object-src 'none'",
  'Cache-Control':'no-store',
};
const server = createServer((request,response) => {
  const resource = routes.get(new URL(request.url,'http://localhost').pathname);
  response.writeHead(resource ? 200 : 404,{...headers,'Content-Type':resource?.type ?? 'text/plain'});
  response.end(resource?.data);
});
let browser, socket;
let result = { outcome:'EXECUTION_ERROR', node:process.version, platform:process.platform, runtimeSha256:digest };
const pending = new Map();
const browserErrors = [];
let counter=0;
function send(method,params={},sessionId) {
  const id=++counter;
  return new Promise((resolve,reject) => {
    const timer=setTimeout(() => {pending.delete(id);reject(new Error(`CDP timeout: ${method}`));},10000);
    pending.set(id,{resolve:x=>{clearTimeout(timer);resolve(x);},reject:x=>{clearTimeout(timer);reject(x);}});
    socket.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));
  });
}
try {
  await new Promise((resolve,reject) => {server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  const origin=`http://127.0.0.1:${server.address().port}`;
  browser=spawn(executable,['--headless=new','--remote-debugging-port=0',`--user-data-dir=${profile}`,
    '--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update',
    '--disable-sync','--disable-extensions','--disable-features=MediaRouter,OptimizationHints','about:blank'],
    {windowsHide:true,stdio:['ignore','ignore','pipe']});
  const endpoint=await new Promise((resolve,reject) => {
    let tail='';
    const timer=setTimeout(() => reject(new Error('Chrome debugger startup timeout')),15000);
    browser.stderr.on('data',chunk => {tail=(tail+chunk).slice(-16384);const match=tail.match(/DevTools listening on (ws:\/\/[^\s]+)/);if(match){clearTimeout(timer);resolve(match[1]);}});
    browser.once('error',error=>{clearTimeout(timer);reject(error);});
    browser.once('exit',()=>{clearTimeout(timer);reject(new Error('Chrome exited before debugger startup'));});
  });
  socket=new WebSocket(endpoint);
  socket.onmessage=event => {
    const message=JSON.parse(event.data);
    if (message.method === 'Runtime.exceptionThrown') browserErrors.push(message.params.exceptionDetails.exception?.description ?? message.params.exceptionDetails.text);
    if (message.method === 'Runtime.consoleAPICalled' && message.params.type === 'error') browserErrors.push(message.params.args.map(arg => arg.value ?? arg.description).join(' ').slice(0,1000));
    if (browserErrors.length > 10) browserErrors.shift();
    const handler=pending.get(message.id);
    if(handler){pending.delete(message.id);message.error?handler.reject(new Error(message.error.message)):handler.resolve(message.result);}
  };
  await new Promise((resolve,reject) => {socket.onopen=resolve;socket.onerror=()=>reject(new Error('CDP connection failed'));});
  const version=await send('Browser.getVersion');
  result.version=version;
  const {targetId}=await send('Target.createTarget',{url:'about:blank'});
  const {sessionId}=await send('Target.attachToTarget',{targetId,flatten:true});
  await send('Page.enable',{},sessionId);
  await send('Runtime.enable',{},sessionId);
  await send('Page.navigate',{url:origin},sessionId);
  const start=Date.now();
  let observed;
  while(Date.now()-start<120000){
    await new Promise(resolve=>setTimeout(resolve,250));
    const reply=await send('Runtime.evaluate',{expression:'globalThis.repro?.done ? globalThis.repro.results : null',returnByValue:true},sessionId);
    if(reply.result.value){observed=reply.result.value;break;}
  }
  if(!observed){
    result.partial=(await send('Runtime.evaluate',{expression:'globalThis.repro',returnByValue:true},sessionId)).result.value;
    throw new Error('Browser test timeout (120 seconds); no correctness verdict');
  }
  result={...result,version,headers,...observed};
} catch(error) { result.error=String(error); }
finally {
  if(browserErrors.length)result.browserErrors=browserErrors;
  if(socket?.readyState===WebSocket.OPEN){try{await send('Browser.close');}catch{}}
  socket?.close();
  if(browser && browser.exitCode===null && browser.signalCode===null){
    const closed=once(browser,'exit').catch(()=>{});
    const graceful=await Promise.race([closed.then(()=>true),new Promise(resolve=>setTimeout(()=>resolve(false),3000))]);
    if(!graceful){browser.kill();await Promise.race([closed,new Promise(resolve=>setTimeout(resolve,3000))]);}
  }
  for(const handler of pending.values())handler.reject(new Error('Diagnostic finished'));
  pending.clear();
  if(server.listening)await new Promise(resolve=>server.close(resolve));
  // Only this mkdtemp-created directory may be removed; never a supplied profile.
  if(dirname(profile)!==output || !profile.startsWith(join(output,'profile-')))throw new Error('Cleanup path invariant failed');
  try { await rm(profile,{recursive:true,force:true,maxRetries:10,retryDelay:200}); result.profileRemoved=true; }
  catch { result.profileRemoved=false; result.cleanupNote='Browser profile remains inside this new output directory; close diagnostic Chrome and remove that directory manually.'; }
  await writeFile(join(output,'result.json'),JSON.stringify(result,null,2));
}
console.log(`Runtime: ${result.package ?? 'local source build'}; SHA-256 ${digest}`);
console.log(`Browser: ${result.version?.product ?? 'unavailable'}; outcome: ${result.outcome}`);
if(result.fixture){
  console.log(`Watched fixture: TestNet genesis; A=${result.fixture.creator}; B=${result.fixture.spender}`);
  console.log(`Watched locks: ${JSON.stringify(result.fixture.watchedScripts)}`);
  for(const phase of ['initial','reopened'])if(result[phase])console.log(`${phase}: expected 7 cells, actual ${result[phase].cells.length}; spent A:5 present=${result[phase].cells.some(c=>c.outPoint===result.fixture.spentOutPoint)}; expected capacity=${result.fixture.expectedCapacity}, actual=${result[phase].capacity}; excess=${result[phase].excessShannons} shannons (${Number(result[phase].excessShannons)/1e8} CKB)`);
  console.log(`Incorrect output: ${result.fixture.spentOutPoint}; reopen preserves result=${result.persistence}`);
  console.log(`Correctness assertions: ${result.assertions.filter(a=>a.passed).length} passed, ${result.assertions.filter(a=>!a.passed).length} failed`);
}
if(result.error)console.error(result.error);
console.log(`Result saved in newly created directory: ${output}`);
console.log(`Disposable profile removed: ${result.profileRemoved}`);
process.exitCode = result.outcome === 'INVARIANTS_PASS' && result.profileRemoved ? 0 : 1;
