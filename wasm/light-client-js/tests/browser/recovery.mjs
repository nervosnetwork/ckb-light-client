// Fresh WO29 application AND database worker. New synthetic databases only.
import {LightClient,LightClientSetScriptsCommand} from '/runtime.js';
const results={assertions:[],startedAt:new Date().toISOString(),package:'fresh WO29 combined local application and PR304 database worker'};
globalThis.repro={done:false,results};
const check=(ok,name)=>{results.assertions.push({name,passed:!!ok});if(!ok)throw Error(name)};
const meta=name=>[224,...new TextEncoder().encode(name)];
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
let client,database,script,baseline,networkSpec=null;
const nativeWorker=Worker,nativeBlob=Blob;
let workers=[],armed=null,checkpointResolve,interruptionMode='commit';
// Commit mode pauses after the durable transaction, before its success reply.
// Abort mode pauses at the first aborted request before its error can reach the
// client worker; termination then finishes the abort. Subsequent readonly checks
// verify the transaction's atomic outcome. Unexpected worker crashes still fail.
const hook=String.raw`
{ const original=IDBObjectStore.prototype.put;
IDBObjectStore.prototype.put=function(value,key){
 const request=original.apply(this,arguments);
 if(value&&Array.isArray(value.key)&&value.key[0]===224&&new TextDecoder().decode(new Uint8Array(value.key.slice(1))).startsWith(__WO29_PHASE__)) {
  const event=__WO29_MODE__==='abort'?'error':'complete';
  this.transaction.addEventListener(event,()=>{
   postMessage({__wo29Checkpoint:__WO29_PHASE__});
   Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0);
  },{once:true,capture:__WO29_MODE__==='abort'});
  if(__WO29_MODE__==='abort')this.transaction.abort();
 }
 return request;
}; }
`;
globalThis.Blob=class extends nativeBlob {
 constructor(parts,options){super(armed&&options?.type?.includes('javascript')?[hook.replaceAll('__WO29_PHASE__',JSON.stringify(armed)).replaceAll('__WO29_MODE__',JSON.stringify(interruptionMode)),...parts]:parts,options);}
};
globalThis.Worker=class extends nativeWorker {
 constructor(...args){super(...args);workers.push(this);this.addEventListener('message',e=>{if(e.data?.__wo29Checkpoint)checkpointResolve?.(e.data.__wo29Checkpoint);});}
};
const config=()=>`chain = "testnet"
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
async function start(){workers=[];client=new LightClient();await client.start(networkSpec?{type:'DevNet',spec:networkSpec,config:config()}:{type:'TestNet',config:config()},`0x${'01'.repeat(32)}`,'error','wss');}
async function stop(){await client.stop();client=null;workers=[];}
function openDb(){return new Promise((resolve,reject)=>{const r=indexedDB.open(database,1);r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});}
async function rows(){const db=await openDb();const records=await new Promise((resolve,reject)=>{const r=db.transaction('main-store','readonly').objectStore('main-store').getAll();r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});db.close();return records;}
async function mutate(operations){const db=await openDb();await new Promise((resolve,reject)=>{const t=db.transaction('main-store','readwrite'),s=t.objectStore('main-store');for(const [kind,key,value]of operations){kind==='delete'?s.delete(key):s.put({key,value},key);}t.oncomplete=resolve;t.onabort=()=>reject(t.error);t.onerror=()=>reject(t.error);});db.close();}
async function raw(name){return (await rows()).find(r=>equal(r.key,meta(name)))?.value;}
async function snapshot(){const key={script,scriptType:'lock'};return {capacity:String(await client.getCellsCapacity(key)),cells:JSON.parse(JSON.stringify(await client.getCells(key,'asc',100),(_,v)=>typeof v==='bigint'?v.toString():v)),transactions:JSON.parse(JSON.stringify(await client.getTransactions(key,'asc',100),(_,v)=>typeof v==='bigint'?v.toString():v))};}
async function seed(label){database=`wo29-recovery-${label}-${crypto.randomUUID()}`;await start();const genesis=await client.getGenesisBlock();script=genesis.transactions.find(t=>t.hash()==='0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f').outputs[5].lock;await client.setScripts([{script,scriptType:'lock',blockNumber:0n}],LightClientSetScriptsCommand.All);baseline=await snapshot();check(!baseline.cells.cells.some(c=>c.outPoint.txHash==='0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f' && BigInt(c.outPoint.index)===5n),`${label}: spent historical output is absent`);check(baseline.transactions.transactions.length>=2,`${label}: real historical genesis creator/spend history`);results[label]={database,baseline};await stop();}
async function failClosed(label){for(const [name,call]of [['cells',()=>client.getCells({script,scriptType:'lock'},'asc',100)],['history',()=>client.getTransactions({script,scriptType:'lock'},'asc',100)],['capacity',()=>client.getCellsCapacity({script,scriptType:'lock'})]]){let error;try{await call();}catch(e){error=String(e);}check(error?.includes('canonical_state:'),`${label}: ${name} returns recovery error, never partial success`);}}
try{
 check(crossOriginIsolated,'COOP/COEP isolation');
 await seed('upgrade');
 const before=await rows();
 const primary=before.filter(r=>[0,160,192].includes(r.key[0]));
 const derived=before.filter(r=>[32,64,96,128].includes(r.key[0]));
 check(derived.length>0,'legacy fixture has genuine indexed history/cells');
 await mutate([['delete',meta('INDEX_ASSOCIATIONS_V1')],['delete',meta('CHAIN_CONTEXT_V1')],...derived.map(r=>['delete',r.key])]);
 await start();
 check((await client.getScripts()).length===1,'upgrade preserves watched scripts');
 check(equal(await snapshot(),baseline),'full genesis rescan restores omitted rows and exact balance/history');
 await stop();
 const after=await rows();
 check(primary.every(row=>after.some(r=>equal(row,r))),'upgrade preserves all original primary transaction/header/height bytes');
 check((await raw('INDEX_ASSOCIATIONS_V1'))?.[0]===1,'format ready only after complete configured-genesis rescan');
 check(await raw('INDEX_REPAIR_V2')===undefined,'completed repair journal removed');
 await start();check(equal(await snapshot(),baseline),'second reopen does not resurrect spent genesis outputs');await stop();

 await seed('earlier-associations');
 const earlierRows=await rows();
 await mutate([['delete',meta('INDEX_RECOVERY_V2')],...earlierRows.filter(r=>[32,64,96,128].includes(r.key[0])).map(r=>['delete',r.key])]);
 check((await raw('INDEX_ASSOCIATIONS_V1'))?.[0]===1,'old association marker alone is insufficient evidence of recoverable watched coverage');
 await start();check(equal(await snapshot(),baseline),'earlier V1 association database also receives complete in-place coverage repair');await stop();
 check((await raw('INDEX_RECOVERY_V2'))?.[0]===2,'new recovery format is installed after complete rescan');

 await seed('old-unpositioned-readiness');
 const oldReadyRows=await rows();
 await mutate([['put',meta('INDEX_RECOVERY_V2'),[1]],...oldReadyRows.filter(r=>[32,64,96,128].includes(r.key[0])).map(r=>['delete',r.key])]);
 await start();check(equal(await snapshot(),baseline),'older recovery readiness cannot certify rows created without positional coverage');await stop();
 check((await raw('INDEX_RECOVERY_V2'))?.[0]===2,'positional readiness requires completed in-place coverage restoration');

 await seed('registration');
 armed='INDEX_REGISTRATION_V2';
 await start();
 const checkpoint=new Promise((resolve,reject)=>{checkpointResolve=resolve;setTimeout(()=>reject(Error('durable registration checkpoint not reached')),15000);});
 const pending=client.setScripts([{script,scriptType:'lock',blockNumber:0n}],LightClientSetScriptsCommand.All);pending.catch(()=>{});
 check(await checkpoint==='INDEX_REGISTRATION_V2','real registration journal transaction committed before interruption');
 for(const worker of workers)worker.terminate();client=null;workers=[];armed=null;checkpointResolve=null;
 check((await raw('INDEX_WRITING_V1'))?.[0]===2,'terminated workers leave registration fence persisted');
 check((await raw('INDEX_REGISTRATION_V2'))?.length>0,'terminated workers leave actual registration intent persisted');
 await start();check(equal(await snapshot(),baseline),'startup replays interrupted registration without changing historical UTXOs/history');await stop();
 check(await raw('INDEX_REGISTRATION_V2')===undefined,'replayed registration intent removed');
 check(await raw('INDEX_UNCERTAIN_V1')===undefined,'journal replay does not latch permanent uncertainty');
 await start();check(equal(await snapshot(),baseline),'registration replay remains idempotent on another worker restart');await stop();

 await seed('pending');
 const rangeKey=[...meta('MATCHED_BLOCKS'),0,0,0,0,0,0,0,1];
 const rangeValue=[1,0,0,0,0,0,0,0,...Array(32).fill(19),0];
 await mutate([['put',rangeKey,rangeValue],['put',meta('MIN_FILTERED_NUMBER'),[1,0,0,0,0,0,0,0]],['put',meta('INDEX_WRITING_V1'),[1]]]);
 await start();await failClosed('interrupted watched range');await stop();
 check((await raw('INDEX_REPAIR_V2'))?.length>0,'ambiguous legacy [1] range becomes saved-target repair, not a completed range');
 await start();await failClosed('second pending-range reopen');await stop();
 check((await raw('INDEX_REPAIR_V2'))?.length>0,'legacy partial-index coverage obligation survives repeated reopen');


 // Native-emitted records use the exact production positional encoder and
 // journal path. Browser network proof creation is not claimed here.
 const positionalFixture=await (await fetch('/rollback-checkpoint.json')).json();
 async function importPositional(label,sourceRows){
  networkSpec=positionalFixture.spec;script=positionalFixture.script;
  database=`wo29-positional-${label}-${crypto.randomUUID()}`;
  await start();await stop();
  await mutate([...(await rows()).map(r=>['delete',r.key]),...sourceRows.map(r=>['put',r.key,r.value])]);
 }
 function repairTargets(bytes){
  const view=new DataView(new Uint8Array(bytes).buffer);let offset=0;
  const u64=()=>{const n=Number(view.getBigUint64(offset,true));offset+=8;return n;};
  const count=u64(),targets=[];
  for(let i=0;i<count;i++){const length=u64();offset+=length;targets.push(u64());}
  return targets;
 }
 for(const mode of ['abort','commit']){
  await importPositional(mode,positionalFixture.positional_legacy_rows);
  const primaryBefore=(await rows()).filter(r=>[0,160,192].includes(r.key[0]));
  armed='MATCHED_BLOCKS';interruptionMode=mode;
  const reached=new Promise((resolve,reject)=>{checkpointResolve=resolve;setTimeout(()=>reject(Error('positional transaction checkpoint missing')),15000);});
  const starting=start();starting.catch(()=>{});
  check(await reached==='MATCHED_BLOCKS',`${mode}: actual IndexedDB positional transaction boundary reached`);
  for(const worker of workers)worker.terminate();client=null;workers=[];armed=null;checkpointResolve=null;interruptionMode='commit';
  check(repairTargets(await raw('INDEX_REPAIR_V2')).includes(2),`${mode}: original coverage target survives interrupted refilter write`);
  const expectedMin=mode==='abort'?2:0;
  check((await raw('MIN_FILTERED_NUMBER'))?.[0]===expectedMin,`${mode}: range and cursor transaction has atomic outcome`);
  const persisted=await rows();
  check(primaryBefore.every(row=>persisted.some(r=>equal(r,row))),`${mode}: interrupted recheck preserves every primary historical byte`);
  await start();await failClosed(`${mode}: unfinished positional refilter`);await stop();
  check((await raw('MIN_FILTERED_NUMBER'))?.[0]===0,`${mode}: restart resumes filter request from saved range start`);
  check(repairTargets(await raw('INDEX_REPAIR_V2')).includes(2),`${mode}: restart preserves target until actual coverage is restored`);
  check(await raw('INDEX_UNCERTAIN_V1')===undefined,`${mode}: retry does not poison uncertainty`);
  await start();await failClosed(`${mode}: repeated positional restart`);await stop();
 }
 await importPositional('partial',positionalFixture.positional_partial_rows);
 const partialBefore=await rows();
 await start();await failClosed('positioned [1] replay checkpoint');await stop();
 check((await raw('INDEX_WRITING_V1'))?.[0]===1,'new positioned [1] replay remains directly resumable');
 const partialAfter=await rows();
 check(partialBefore.filter(r=>r.key[0]===224&&new TextDecoder().decode(new Uint8Array(r.key.slice(1))).startsWith('MATCHED_BLOCKS')).every(row=>partialAfter.some(r=>equal(r,row))),'indexed position flag and ambiguous tail both survive real worker reopen');
 await start();await failClosed('second positioned [1] restart');await stop();
 await importPositional('complete',positionalFixture.positional_final_rows);
 await start();const complete=await snapshot();
 check(complete.capacity==='0'&&complete.cells.cells.length===0,'completed native proof/body checkpoint has no resurrected spent cells in browser');
 check(complete.transactions.transactions.length===2,'browser reads complete restored creator/spend history');
 check(await raw('INDEX_REPAIR_V2')===undefined,'fully restored positional checkpoint has no repair fence');
 await stop();await start();check(equal(await snapshot(),complete),'completed positional history is stable through another actual worker restart');await stop();
 networkSpec=null;

 await seed('bare-transition');
 const scriptRow=(await rows()).find(r=>r.key[0]===224&&new TextDecoder().decode(new Uint8Array(r.key.slice(1,15)))==='FILTER_SCRIPTS');
 check(!!scriptRow,'locate saved watched cursor');
 await mutate([['put',scriptRow.key,[0,0,0,0,0,0,0,2]],['put',meta('CHAIN_TRANSITION_V1'),[1]]]);
 await start();await failClosed('bare legacy rollback requires coverage repair');await client.setScripts([{script,scriptType:'lock',blockNumber:2n}],LightClientSetScriptsCommand.Partial);await failClosed('registration start height cannot certify repaired coverage');await stop();
 check((await raw('INDEX_REPAIR_V2'))?.length>0,'bare transition becomes durable in-place repair');
 check(await raw('INDEX_ASSOCIATIONS_V1')===undefined,'unrestored historical coverage is not marked migrated');
 await start();await failClosed('repeated bare-marker repair');await stop();
 // The checkpoint was emitted by native accept_with_rollback, interrupted
 // before its final accepted-state batch. These are trusted test headers with
 // DummyPoW; protocol proof validation is covered separately in native tests.
 const rollbackFixture=await (await fetch('/rollback-checkpoint.json')).json();
 networkSpec=rollbackFixture.spec;script=rollbackFixture.script;
 database=`wo29-recovery-rollback-${crypto.randomUUID()}`;
 await start();await stop();
 await mutate(rollbackFixture.rows.map(row=>['put',row.key,row.value]));
 const rollbackPrimary=rollbackFixture.rows.filter(row=>[0,160,192].includes(row.key[0]));
 check((await raw('CHAIN_ACCEPT_V2'))?.length>0,'real exported rollback intent is present');
 armed='CHAIN_CONTEXT_V1';
 const rollbackCheckpoint=new Promise((resolve,reject)=>{checkpointResolve=resolve;setTimeout(()=>reject(Error('accepted rollback checkpoint not reached')),30000);});
 const pendingStart=start();pendingStart.catch(()=>{});
 check(await rollbackCheckpoint==='CHAIN_CONTEXT_V1','browser accepted-state/window/context batch commits before worker termination');
 for(const worker of workers)worker.terminate();client=null;workers=[];armed=null;checkpointResolve=null;
 check(equal((await raw('LAST_STATE')).slice(32),rollbackFixture.candidate_tip),'interrupted browser rollback stores the exact journal candidate');
 check(await raw('CHAIN_ACCEPT_V2')===undefined && await raw('CHAIN_TRANSITION_V1')===undefined,'accepted tip and both rollback markers finish atomically');
 check((await raw('INDEX_REPAIR_V2'))?.length>0,'higher saved coverage target survives accepted rollback');
 await start();
 check((await client.getTipHeader()).number===3n,'restart retains the accepted candidate height');
 await failClosed('accepted rollback still needs historical coverage');await stop();
 const rolledRows=await rows();
 check(rollbackPrimary.every(row=>rolledRows.some(r=>equal(r,row))),'browser rollback/restart preserves every historical transaction/header/height record');
 check(rolledRows.some(r=>equal(r.key,rollbackFixture.creator_key)&&equal(r.value,rollbackFixture.creator_bytes)),'multi-transaction historical creator bytes are retained');
 check(await raw('INDEX_RECOVERY_V2')===undefined,'rollback repair cannot certify coverage by clearing a marker');
 await start();await failClosed('second rollback repair restart');await stop();
 check(equal((await raw('LAST_STATE')).slice(32),rollbackFixture.candidate_tip),'repeated recovery does not change accepted candidate');

 // Exact before/after rows come from the real native acceptance encoder and
 // batch path. This tests IndexedDB atomicity and actual WASM startup replay;
 // network fork-proof construction is tested separately in native protocols.
 check(rollbackFixture.target_fix?.length===2 && rollbackFixture.intent_delta?.length===3,
  'shorter-target fixture contains the exact three-key acceptance transition');
 async function importTarget(label,sourceRows){
  database=`wo29-target-fix-${label}-${crypto.randomUUID()}`;
  await start();await stop();
  await mutate([...(await rows()).map(r=>['delete',r.key]),...sourceRows.map(r=>['put',r.key,r.value])]);
 }
 async function applyIntentDelta(abort){
  const db=await openDb();
  await new Promise((resolve,reject)=>{
   const t=db.transaction('main-store','readwrite'),s=t.objectStore('main-store');
   const first=rollbackFixture.intent_delta.find(row=>equal(row.key,meta('INDEX_REPAIR_V2')));
   const request=s.put(first,first.key);
   request.onsuccess=()=>{
    if(abort){t.abort();return;}
    for(const row of rollbackFixture.intent_delta)if(row!==first)s.put(row,row.key);
   };
   t.oncomplete=()=>abort?reject(Error('expected intent transaction abort')):resolve();
   t.onabort=()=>abort?resolve():reject(t.error);
   t.onerror=()=>{if(!abort)reject(t.error);};
  });db.close();
 }
 for(const mode of ['abort','commit']){
  const committed=mode==='commit',fixture=rollbackFixture.target_fix[committed?1:0];
  await importTarget(mode,rollbackFixture.target_fix[0].rows);
  const oldPrimary=(await rows()).filter(row=>[0,160,192].includes(row.key[0]));
  await applyIntentDelta(!committed);
  check(repairTargets(await raw('INDEX_REPAIR_V2'))[0]===(committed?1:2),`${mode}: target change has the atomic intent outcome`);
  check(!!(await raw('CHAIN_ACCEPT_V2'))===committed,`${mode}: acceptance intent is coupled with shortened targets`);
  check(!!(await raw('CHAIN_TRANSITION_V1'))===committed,`${mode}: transition fence is coupled with shortened targets`);
  if(committed){
   armed='CHAIN_CONTEXT_V1';
   const reached=new Promise((resolve,reject)=>{checkpointResolve=resolve;setTimeout(()=>reject(Error('shorter acceptance replay checkpoint missing')),30000);});
   const starting=start();starting.catch(()=>{});
   check(await reached==='CHAIN_CONTEXT_V1','shorter intent replay commits accepted state before worker interruption');
   for(const worker of workers)worker.terminate();client=null;workers=[];armed=null;checkpointResolve=null;
   check(equal((await raw('LAST_STATE')).slice(32),fixture.expected_tip),'shorter candidate remains accepted across real worker termination');
   check(await raw('CHAIN_ACCEPT_V2')===undefined && await raw('CHAIN_TRANSITION_V1')===undefined,'shorter replay removes both acceptance markers with accepted context');
  }
  await start();
  check((await client.getTipHeader()).number===BigInt(committed?1:2),`${mode}: restart uses the actually accepted chain`);
  await failClosed(`${mode}: shorter-target recovery before coverage`);await stop();
  check(repairTargets(await raw('INDEX_REPAIR_V2'))[0]===(committed?1:2),`${mode}: correct old/new target survives restart`);
  const repairedRows=await rows();
  check(oldPrimary.every(row=>repairedRows.some(r=>equal(r,row))),`${mode}: target recovery preserves all primary history bytes`);
  await start();await failClosed(`${mode}: repeated shorter-target restart`);await stop();
  await importTarget(`${mode}-prefix`,fixture.prefix_rows);
  await start();
  if(committed){
   check(String(await client.getCellsCapacity({script,scriptType:'lock'}))==='100','new accepted height 1 legitimately has the unspent creator');
  }else{
   await failClosed('old accepted height 2 after only creator replay');
   check(repairTargets(await raw('INDEX_REPAIR_V2'))[0]===2,'old height-2 spend cannot be dropped after partial honest replay');
  }
  await stop();
  await importTarget(`${mode}-complete`,fixture.complete_rows);
  await start();const complete=await snapshot();
  check(complete.capacity===String(fixture.expected_capacity),`${mode}: complete old/new chain has the exact correct capacity`);
  check(complete.cells.cells.length===(committed?1:0),`${mode}: spent outputs are not resurrected on the old chain`);
  check(complete.transactions.transactions.length===(committed?1:2),`${mode}: completed history follows the accepted chain`);
  check(await raw('INDEX_REPAIR_V2')===undefined,`${mode}: readiness follows complete applicable coverage`);
  await stop();await start();check(equal(await snapshot(),complete),`${mode}: completed coverage survives another worker reopen`);await stop();
 }
 networkSpec=null;
 results.outcome='INVARIANTS_PASS';
}catch(error){results.outcome='EXECUTION_ERROR';results.error=String(error);}
finally{armed=null;if(client){for(const worker of workers)worker.terminate();client=null;}results.finishedAt=new Date().toISOString();document.querySelector('#result').textContent=JSON.stringify(results,null,2);globalThis.repro.done=true;}
