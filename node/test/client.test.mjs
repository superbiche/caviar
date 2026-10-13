// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas
import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readlinkSync, existsSync, mkdtempSync, mkdirSync, cpSync, readFileSync, writeFileSync, rmSync, chmodSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
const dir = process.env.CAVIAR_NODE_PACKAGE;
assert.ok(dir, 'explicit source or installed package under test required');
const { Client, Pool, CaviarError, decodeJson } = await import(pathToFileURL(dir + '/lib/index.js'));
const key = Uint8Array.from({length: 32}, (_, i) => i);
const code = c => e => e instanceof CaviarError && e.code === c && e.message === c;
function pids() {
  const found=[];
  for (const pid of readdirSync('/proc').filter(n=>/^\d+$/.test(n))) {
    try { if (readlinkSync('/proc/'+pid+'/exe') === dir+'/_bin/caviar-redact-worker') found.push(Number(pid)); } catch {}
  }
  return found;
}
const baseline = pids();
test('configuration fails closed', async () => {
  for (const k of [undefined, 'private', new Uint8Array(15), new Uint8Array(65537)]) assert.throws(()=>new Client(k),code('invalid_key'));
  assert.throws(()=>new Client(null),code('key_required'));
  for (const timeout of [0,-1,NaN,Infinity,61,true,'5']) assert.throws(()=>new Client(key,{timeout}),code('invalid_timeout'));
  for (const size of [0,33,1.5,true,NaN]) assert.throws(()=>new Pool(key,size,{acquireTimeout:0}),code('invalid_size'));
  for (const acquireTimeout of [-1,61,NaN,Infinity,true,'0']) assert.throws(()=>new Pool(key,1,{acquireTimeout}),code('invalid_acquire_timeout'));
});
test('round trip, key copy, big integers, stable closure', async () => {
  const caller=key.slice(), c=new Client(caller); caller.fill(0);
  try {
    const text='Authorization: Bearer '+Array.from({length:40},(_,i)=>(i%16).toString(16)).join('');
    const [result,hits]=await c.string(text); assert.notEqual(result,text); assert.ok(hits.length);
    const d=new Client(key); try { assert.deepEqual(await d.string(text),[result,hits]); } finally { await d.close(); }
    assert.deepEqual(await c.string(result),[result,[]]);
    assert.deepEqual(await c.value({ordinary:9007199254740993n,small:3}),[{ordinary:9007199254740993n,small:3},[]]);
    for (const input of [NaN,Infinity,undefined,()=>{},9007199254740992, '\ud800', new Date()]) await assert.rejects(c.value(input),code('unsupported_value'));
    let touched=false; const accessor={get ordinary(){touched=true;return 1;}};
    await assert.rejects(c.value(accessor),code('unsupported_value')); assert.equal(touched,false);
    const cycle=[]; cycle.push(cycle); await assert.rejects(c.value(cycle),code('unsupported_value'));
    await assert.rejects(c.string('x'.repeat((2<<20)+1)),code('request_too_large'));
    assert.deepEqual(await c.string('ordinary'),['ordinary',[]]);
  } finally { await c.close(); }
  await assert.rejects(c.string('ordinary'),code('closed')); await c.close();
});
test('busy refusal and close during a call', async () => {
  const c=new Client(key); await c.string('warmup');
  const running=c.string('ordinary'); await assert.rejects(c.string('ordinary'),code('busy')); await running;
  process.kill(c.child.pid,'SIGSTOP');
  const blocked=c.string('ordinary'); const rejected=assert.rejects(blocked,code('closed'));
  await c.close(); await rejected;
});
test('deadline kills stopped worker, reaps it, restarts next generation', {timeout:2000}, async () => {
  const c=new Client(key,{timeout:0.15});
  try {
    await c.string('warmup'); const pid=c.child.pid; process.kill(pid,'SIGSTOP');
    const start=performance.now(); await assert.rejects(c.string('ordinary'),code('deadline'));
    const elapsed=performance.now()-start;
    assert.ok(elapsed>=100 && elapsed<1000,'deadline wall bound'); assert.equal(existsSync('/proc/'+pid),false);
    assert.deepEqual(await c.string('ordinary'),['ordinary',[]]); assert.notEqual(c.child.pid,pid);
  } finally { await c.close(); }
});
test('pool concurrent admission, bounded wait, terminal waiter release', {timeout:3000}, async () => {
  const p=new Pool(key,2,{acquireTimeout:0.08,timeout:1});
  try {
    await Promise.all([p.string('warmup'),p.string('warmup')]);
    assert.equal(new Set(p.clients.map(c=>c.child.pid)).size,2);
    for (const c of p.clients) process.kill(c.child.pid,'SIGSTOP');
    const a=p.string('ordinary'), b=p.string('ordinary');
    const ar=assert.rejects(a,code('closed')),br=assert.rejects(b,code('closed'));
    const start=performance.now(); await assert.rejects(p.string('ordinary'),code('busy'));
    assert.ok(performance.now()-start>=50 && performance.now()-start<600);
    const queued=assert.rejects(p.string('ordinary'),code('closed'));
    await p.close(); await Promise.all([ar,br,queued]);
    await assert.rejects(p.string('ordinary'),code('closed'));
  } finally { await p.close(); }
});
test('pool parallel progress defeats serialization', {timeout:3000}, async () => {
  const p=new Pool(key,2,{acquireTimeout:1,timeout:0.2});
  try {
    await Promise.all([p.string('warmup'),p.string('warmup')]);
    // Warmups finish in either order; suspend the next admitted worker.
    process.kill(p.free[0].child.pid,'SIGSTOP');
    const stalled=p.string('ordinary'); const rejected=assert.rejects(stalled,code('deadline'));
    const start=performance.now(); assert.deepEqual(await p.string('ordinary'),['ordinary',[]]);
    assert.ok(performance.now()-start<120,'healthy worker was serialized behind stalled call'); await rejected;
    assert.deepEqual(await p.string('ordinary'),['ordinary',[]]);
  } finally { await p.close(); }
});


test('strict wire JSON and domain refusals', async () => {
  for (const text of ['{"x":1,"x":2}', '{"x":1,"\\u0078":2}', '{"x":"\\ud800"}', 'NaN', '{"x":1} trailing', '1e10000']) {
    assert.throws(()=>decodeJson(Buffer.from(text)),code('protocol'));
  }
  assert.throws(()=>decodeJson(Uint8Array.of(0xff)),code('protocol'));
  assert.throws(()=>decodeJson(Buffer.from('{}'),0),code('deadline'));
  assert.deepEqual(decodeJson(Buffer.from('{"ordinary":9007199254740993}')),{ordinary:9007199254740993n});
  const c=new Client(key);
  try {
    await assert.rejects(c.value(new Proxy({},{})),code('unsupported_value'));
    const alias=[];let tree=alias;for(let i=0;i<24;i++)tree=[tree,tree];
    await assert.rejects(c.value(tree),code('request_too_large'));
    let deep=null;for(let i=0;i<502;i++)deep=[deep];
    await assert.rejects(c.value(deep),code('unsupported_value'));
    await assert.rejects(c.value([,1]),code('unsupported_value'));
    assert.equal(c.child,null,'invalid input must not start a worker');
  } finally { await c.close(); }
});

test('wrong identity and malformed frame matrix through real private pipes', {timeout:15000}, async () => {
  mkdirSync('tmp/ts/unit-fakes',{recursive:true});
  const fixture=mkdtempSync('tmp/ts/unit-fakes/package-');
  for(const name of ['lib','package.json','_bin'])cpSync(dir+'/'+name,fixture+'/'+name,{recursive:true});
  const absolute=new URL(fixture+'/',pathToFileURL(process.cwd()+'/')).pathname;
  const {Client:FakeClient}=await import(pathToFileURL(absolute+'lib/index.js'));
  const manifest=JSON.parse(readFileSync(fixture+'/_bin/manifest.json'));
  try {
    for(const mode of ['identity','wrong_id','wrong_generation','extra','duplicate','null','bad_hits','duplicate_hits','oversized','zero','invalid_utf8','death','core']) {
      const script=`#!${process.execPath}
import {readFileSync} from 'node:fs';
const mode=${JSON.stringify(mode)};
const identity=JSON.parse(readFileSync(new URL('manifest.json',import.meta.url))).identity;
let bytes=Buffer.alloc(0);
function frame(body){const data=Buffer.from(body),head=Buffer.alloc(8);head.writeBigUInt64BE(BigInt(data.length));process.stdout.write(Buffer.concat([head,data]));}
process.stdin.on('data',chunk=>{
 bytes=Buffer.concat([bytes,chunk]);
 while(bytes.length>=8){const n=Number(bytes.readBigUInt64BE());if(bytes.length<8+n)return;
 const request=JSON.parse(bytes.subarray(8,8+n));bytes=bytes.subarray(8+n);
 if(request.kind==='init'){frame(JSON.stringify({...identity,kind:'ready',generation:request.generation,release:mode==='identity'?'incorrect':identity.release}));continue;}
 if(mode==='death'){process.exit(0);}
 if(mode==='oversized'||mode==='zero'){const head=Buffer.alloc(8);head.writeBigUInt64BE(mode==='zero'?0n:BigInt(9<<20));process.stdout.write(head);continue;}
 if(mode==='invalid_utf8'){const head=Buffer.alloc(8);head.writeBigUInt64BE(1n);process.stdout.write(Buffer.concat([head,Buffer.from([255])]));continue;}
 const reply={kind:'result',generation:request.generation,id:request.id,result:request.text??request.value,hits:[]};
 if(mode==='wrong_id')reply.id='wrong';
 if(mode==='wrong_generation')reply.generation='wrong';
 if(mode==='extra')reply.extra=true;
 if(mode==='bad_hits')reply.hits=[{rule:'test',count:0}];
 if(mode==='duplicate_hits')reply.hits=[{rule:'test',count:1},{rule:'test',count:1}];
 if(mode==='core'){delete reply.result;delete reply.hits;reply.error='core_failure';}
 let raw=JSON.stringify(reply);
 if(mode==='duplicate')raw=raw.replace('"kind":"result"','"kind":"result","kind":"result"');
 if(mode==='null')raw='null';
 frame(raw);
 }
});
`;
      writeFileSync(fixture+'/_bin/caviar-redact-worker',script,{mode:0o755});
      const raw=Buffer.from(script);
      writeFileSync(fixture+'/_bin/manifest.json',JSON.stringify({...manifest,size:raw.length,sha256:createHash('sha256').update(raw).digest('hex')}));
      const c=new FakeClient(key,{timeout:1});
      try {
        await assert.rejects(c.string('ordinary'),e=>e.code===(mode==='identity'?'identity':mode==='death'?'worker_failure':mode==='core'?'core_failure':'protocol'));
      }finally{await c.close();}
    }
    // Incorrect workerRelease refuses even if the npm version itself is valid.
    const packageMeta=JSON.parse(readFileSync(fixture+'/package.json'));
    writeFileSync(fixture+'/package.json',JSON.stringify({...packageMeta,workerRelease:'9.9.9'}));
    const metadataClient=new FakeClient(key);
    try{await assert.rejects(metadataClient.string('ordinary'),e=>e.code==='artifact');assert.equal(metadataClient.child,null);}finally{await metadataClient.close();}
    writeFileSync(fixture+'/package.json',JSON.stringify(packageMeta));
    // Worker bytes tampering without updating the manifest must refuse before spawn.
    writeFileSync(fixture+'/_bin/caviar-redact-worker','changed');
    const c=new FakeClient(key);
    try{await assert.rejects(c.string('ordinary'),e=>e.code==='artifact');assert.equal(c.child,null);}finally{await c.close();}
  }finally{rmSync(fixture,{recursive:true,force:true});}
});

test('normal host exit kills its worker', {timeout:3000}, async () => {
  const module=pathToFileURL(dir+'/lib/index.js').href;
  const script=`import {Client} from ${JSON.stringify(module)};const c=new Client(new Uint8Array(32));await c.string('ordinary');process.stdout.write(String(c.child.pid)+'\\n',()=>process.exit(0));`;
  const host=spawn(process.execPath,['--input-type=module','-e',script],{stdio:['ignore','pipe','ignore']});
  let out='';host.stdout.on('data',b=>{out+=b;});
  try {
    const rc=await new Promise((resolve,reject)=>{host.once('error',reject);host.once('close',resolve);});assert.equal(rc,0);
    const pid=Number(out.trim());assert.ok(Number.isInteger(pid)&&pid>0);
    for(let i=0;i<50&&existsSync('/proc/'+pid+'/exe');i++)await delay(10);
    assert.equal(existsSync('/proc/'+pid+'/exe'),false);
  }finally{host.kill('SIGKILL');}
});

test('unclosed idle Client permits natural host exit and reaps worker', {timeout:4000}, async () => {
  const module=pathToFileURL(dir+'/lib/index.js').href;
  const script=`import {Client} from ${JSON.stringify(module)};const c=new Client(new Uint8Array(32));await c.string('ordinary');process.stdout.write(String(c.child.pid)+'\\n');`;
  const host=spawn(process.execPath,['--input-type=module','-e',script],{stdio:['ignore','pipe','ignore']});
  let out='';host.stdout.on('data',b=>{out+=b;});
  const exited=new Promise((resolve,reject)=>{host.once('error',reject);host.once('close',resolve);});
  let timer;
  try {
    const rc=await Promise.race([exited,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('idle worker prevented natural exit')),1800);})]);
    assert.equal(rc,0);const pid=Number(out.trim());assert.ok(Number.isInteger(pid)&&pid>0);
    for(let i=0;i<50&&existsSync('/proc/'+pid+'/exe');i++)await delay(10);
    assert.equal(existsSync('/proc/'+pid+'/exe'),false);
  } finally {clearTimeout(timer);host.kill('SIGKILL');await exited;}
});
test('worker without exec permission refuses artifact before init', async () => {
  mkdirSync('tmp/ts',{recursive:true});const fixture=mkdtempSync('tmp/ts/noexec-');
  let c;
  try {
    cpSync(dir,fixture,{recursive:true});chmodSync(fixture+'/_bin/caviar-redact-worker',0o644);
    const {Client:FixtureClient}=await import(pathToFileURL(fixture+'/lib/index.js'));
    c=new FixtureClient(key);await assert.rejects(c.string('ordinary'),e=>e.code==='artifact'&&e.message==='artifact');
    assert.equal(c.child,null);
  } finally {if(c)await c.close();rmSync(fixture,{recursive:true,force:true});}
});
test('no live package workers after suite',()=>assert.deepEqual(pids(),baseline));
