// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas
import { createReadStream, readFileSync, writeFileSync, realpathSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { relative, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { isDeepStrictEqual } from 'node:util';
const [packageDir, oraclePath, output] = process.argv.slice(2);
const installed = resolve('tmp/delivery-work/installed/node/node_modules/@superbiche-private/caviar');
if (!packageDir || !oraclePath || !output || resolve(packageDir) !== installed || realpathSync(packageDir) !== installed) throw new Error('exact installed artifact required');
const {Client,CaviarError,decodeJson}=await import(pathToFileURL(packageDir+'/lib/index.js'));
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
async function digest(path) { const h=createHash('sha256'); for await(const chunk of createReadStream(path))h.update(chunk);return h.digest('hex'); }
const pins=JSON.parse(readFileSync('docs/UPSTREAM.json'));
const meta=JSON.parse(readFileSync(oraclePath.replace(/\.jsonl$/,'.meta.json')));
if(meta.sha256!==await digest(oraclePath) || meta.reference_sha256!==pins.reference_sha256 || meta.corpus_sha256!==pins.corpus_sha256 || !meta.oracle_python.startsWith('3.14.'))throw new Error('oracle pin mismatch');
if(meta.generator_sha256!==sha(readFileSync('scripts/campaign_inputs.py')))throw new Error('generator pin mismatch');
const identity=JSON.parse(readFileSync(packageDir+'/_bin/manifest.json')).identity;
const packageMeta=JSON.parse(readFileSync(packageDir+'/package.json'));
if(packageMeta.name!=='@superbiche-private/caviar'||packageMeta.workerRelease!==identity.release)throw new Error('worker release mismatch');
const members=['package.json','README.md','LICENSE','THIRD-PARTY-NOTICES.md','src/index.ts','lib/index.js','lib/index.d.ts','_bin/caviar-redact-worker','_bin/manifest.json'];
const artifacts=Object.fromEntries(members.map(n=>[n,sha(readFileSync(packageDir+'/'+n))]));
const clients=[new Client(null,{allowPlain:true}),new Client(Uint8Array.from({length:32},(_,i)=>i))];
const result={node:process.version,package_name:packageMeta.name,package_version:packageMeta.version,worker_release:packageMeta.workerRelease,identity,artifact_hashes:artifacts,package_path:relative(process.cwd(),packageDir),qualification_generator_sha256:sha(readFileSync('scripts/qualify_node.mjs')),oracle:meta,comparisons:0,mismatches:[],samples_per_row:30,warmups:1,p4_rows:[],seed:meta.seed};
const labels=new Set();
try {
  const lines=createInterface({input:createReadStream(oraclePath),crlfDelay:Infinity});
  for await(const line of lines) {
    if(Buffer.byteLength(line)>16*1024*1024)throw new Error('oracle line cap');
    const row=decodeJson(Buffer.from(line)),label={id:row.id,mode:row.mode,keyed:row.keyed};
    const name=JSON.stringify(label);if(labels.has(name))throw new Error('duplicate oracle label');labels.add(name);
    const expected=row.error??row.expected;
    async function invoke(){try{return await clients[Number(row.keyed)][row.mode==='text'?'string':'value'](row.data);}catch(e){if(e instanceof CaviarError)return e.code;throw e;}}
    const check=actual=>{if(!isDeepStrictEqual(actual,expected)) {result.mismatches.push(label);throw new Error('installed Node parity mismatch; values withheld');}};
    check(await invoke());result.comparisons++;
    if(meta.kind==='corpus'&&row.perf) {
      check(await invoke());const samples=[];
      for(let i=0;i<30;i++){const start=performance.now();const actual=await invoke();samples.push(performance.now()-start);check(actual);}
      const sorted=[...samples].sort((a,b)=>a-b),median=(sorted[14]+sorted[15])/2;
      result.p4_rows.push({...label,bytes:row.bytes,max_ms:row.max_ms,samples_ms:samples,median_ms:median,ratio:median/row.max_ms});
    }
  }
}finally{
  await Promise.all(clients.map(c=>c.close()));
  result.cases=meta.kind==='corpus'?result.comparisons:result.comparisons/4;
  result.worst_ratio=Math.max(0,...result.p4_rows.map(r=>r.ratio));
  result.p4_over_budget=result.p4_rows.filter(r=>r.ratio>1).map(({id,mode,keyed,ratio})=>({id,mode,keyed,ratio}));
  writeFileSync(output,JSON.stringify(result,null,2)+'\n');
}
if(result.comparisons!==meta.records || result.mismatches.length || result.p4_over_budget.length || (meta.kind==='corpus'&&result.p4_rows.length!==326))throw new Error('incomplete or over-budget Node qualification');
console.log(JSON.stringify({kind:meta.kind,comparisons:result.comparisons,mismatches:0,p4_rows:result.p4_rows.length,worst_ratio:result.worst_ratio}));
