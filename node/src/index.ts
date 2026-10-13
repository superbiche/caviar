// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFile, lstat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { types } from 'node:util';

export type Json = null | boolean | string | number | bigint | Json[] | { [key: string]: Json };
export type Hit = { rule: string; count: number };
export type Result<T = Json> = [T, Hit[]];
export type Options = { timeout?: number; allowPlain?: boolean };
export type PoolOptions = Options & { acquireTimeout: number };
const REQUEST_CAP = 2 << 20, RESPONSE_CAP = 8 << 20;
const processes = new Set<any>();
process.once('exit', () => { for (const child of processes) child.kill('SIGKILL'); });
export class CaviarError extends Error {
  readonly code: string;
  constructor(code: string) { super(code); this.name = 'CaviarError'; this.code = code; }
}
function fail(code: string): never { throw new CaviarError(code); }
function remaining(deadline: number): number {
  const left = deadline - performance.now();
  if (left <= 0) fail('deadline');
  return left;
}
function options(key: Uint8Array | null, opts: Options): {key: Buffer | null; timeout: number} {
  if (!opts || typeof opts !== 'object') fail('invalid_timeout');
  if (key !== null && typeof key === 'object' && types.isProxy(key)) fail('invalid_key');
  if (key === null) { if (opts.allowPlain !== true) fail('key_required'); }
  else if (!(key instanceof Uint8Array) || key.length < 16 || key.length > 65536) fail('invalid_key');
  const timeout = opts.timeout ?? 5;
  if (typeof timeout !== 'number' || !Number.isFinite(timeout) || timeout <= 0 || timeout > 60) fail('invalid_timeout');
  return {key: key === null ? null : Buffer.from(key), timeout};
}
// Snapshot only JSON representations, never invoke getters, toJSON or custom prototypes.
function domain(value: unknown, cap: number, deadline: number): Json {
  let budget = 0;
  const active = new Set<object>();
  function visit(item: any, depth: number): Json {
    remaining(deadline);
    if (depth > 500) fail('unsupported_value');
    if (++budget > cap) fail('request_too_large');
    if (item === null || typeof item === 'boolean') return item;
    if (typeof item === 'string') {
      if (!item.isWellFormed()) fail('unsupported_value');
      if (item.length > cap) fail('request_too_large');
      budget += Buffer.byteLength(item);
    } else if (typeof item === 'bigint') {
      if (item > (1n << 14000n) || item < -(1n << 14000n)) fail('unsupported_value');
      budget += item.toString().length;
    } else if (typeof item === 'number') {
      if (!Number.isFinite(item) || (Number.isInteger(item) && !Number.isSafeInteger(item))) fail('unsupported_value');
      budget += String(item).length;
    } else if (typeof item === 'object') {
      if (types.isProxy(item)) fail('unsupported_value');
      if (active.has(item)) fail('unsupported_value');
      const array = Array.isArray(item), proto = Object.getPrototypeOf(item);
      if ((!array && proto !== Object.prototype && proto !== null) || (array && proto !== Array.prototype)) fail('unsupported_value');
      const descriptors = Object.getOwnPropertyDescriptors(item);
      const keys = Reflect.ownKeys(descriptors);
      if (keys.length > cap) fail('request_too_large');
      if (keys.some(k => typeof k !== 'string')) fail('unsupported_value');
      if (array && (item.length > cap || keys.length !== item.length + 1)) fail('unsupported_value');
      active.add(item);
      const result: any = array ? [] : Object.create(null);
      for (const key of keys as string[]) {
        if (array && key === 'length') continue;
        const d = descriptors[key];
        if (!('value' in d) || !d.enumerable || (array && !/^(0|[1-9][0-9]*)$/.test(key))) fail('unsupported_value');
        visit(key, depth + 1);
        result[key] = visit(d.value, depth + 1);
      }
      active.delete(item);
      return result;
    } else fail('unsupported_value');
    if (budget > cap) fail('request_too_large');
    return item;
  }
  return visit(value, 0);
}
function encode(value: unknown, deadline: number): Buffer {
  remaining(deadline);
  const data = Buffer.from(JSON.stringify(value, (_, v) => typeof v === 'bigint' ? JSON.rawJSON(v.toString()) : v));
  remaining(deadline);
  if (data.length > REQUEST_CAP) fail('request_too_large');
  const header = Buffer.alloc(8); header.writeBigUInt64BE(BigInt(data.length));
  return Buffer.concat([header, data]);
}
// JSON.parse supplies syntax and exact numeric source; this overlay refuses duplicate keys.
function uniqueKeys(text: string): void {
  let i = 0;
  const ws = () => { while (/\s/.test(text[i] ?? '') && i < text.length) i++; };
  const quoted = () => {
    const start = i++;
    while (i < text.length) { if (text[i++] === '"') return JSON.parse(text.slice(start, i)); if (text[i - 1] === '\\') i++; }
    fail('protocol');
  };
  function value(depth: number): void {
    if (depth > 500) fail('protocol');
    ws();
    if (text[i] === '"') { quoted(); return; }
    const open = text[i];
    if (open === '{' || open === '[') {
      i++; ws(); const close = open === '{' ? '}' : ']'; const seen = new Set();
      if (text[i] === close) { i++; return; }
      while (i < text.length) {
        ws();
        if (open === '{') {
          if (text[i] !== '"') fail('protocol');
          const k = quoted(); if (seen.has(k)) fail('protocol'); seen.add(k);
          ws(); if (text[i++] !== ':') fail('protocol');
        }
        value(depth + 1); ws();
        if (text[i] === close) { i++; return; }
        if (text[i++] !== ',') fail('protocol');
      }
      fail('protocol');
    }
    const start = i;
    while (i < text.length && !/[\s,\]}]/.test(text[i])) i++;
    if (start === i) fail('protocol');
  }
  value(0); ws(); if (i !== text.length) fail('protocol');
}
export function decodeJson(data: Uint8Array): Json {
  try {
    const text = new TextDecoder('utf-8', {fatal: true}).decode(data);
    uniqueKeys(text);
    const value = JSON.parse(text, (_, v, c) => {
      if (typeof v === 'number') {
        if (!Number.isFinite(v)) fail('protocol');
        if (/^-?(0|[1-9][0-9]*)$/.test(c.source) && !Number.isSafeInteger(v)) return BigInt(c.source);
      }
      return v;
    });
    domain(value, RESPONSE_CAP, performance.now() + 60000);
    return value;
  } catch { fail('protocol'); }
}
function exact(value: any, names: string[]): boolean {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === names.length && names.every(n => Object.hasOwn(value, n));
}
export class Client {
  private key: Buffer | null;
  private timeout: number;
  private owner = process.pid;
  private closed = false;
  private busy = false;
  private child: any = null;
  private generation = '';
  private seq = 0n;
  private pending: any = null;
  private chunks: Buffer[] = [];
  private buffered = 0;
  private expected: number | null = null;
  private timer: any = null;
  private reaping: Promise<void> = Promise.resolve();
  constructor(key: Uint8Array | null, opts: Options = {}) {
    const validated = options(key, opts); this.key = validated.key; this.timeout = validated.timeout;
  }
  async string(text: string): Promise<Result<string>> {
    if (typeof text !== 'string') fail('unsupported_value');
    return this.call('text', text) as Promise<Result<string>>;
  }
  async value(value: Json): Promise<Result> { return this.call('value', value); }
  close(): Promise<void> {
    this.closed = true; this.key?.fill(0); this.key = null;
    this.stop('closed'); return this.reaping;
  }
  private stop(code: string): void {
    clearTimeout(this.timer); this.timer = null;
    const pending = this.pending; this.pending = null;
    pending?.reject(new CaviarError(code));
    const child = this.child; this.child = null;
    this.chunks = []; this.buffered = 0; this.expected = null; this.seq = 0n;
    if (child) {
      this.reaping = new Promise(resolve => {
        if (child._caviarClosed || child.exitCode !== null || child.signalCode !== null) { processes.delete(child); resolve(); }
        else child.once('close', () => { processes.delete(child); resolve(); });
      });
      if (process.pid === this.owner) child.kill('SIGKILL');
      else { child.stdin?.destroy(); child.stdout?.destroy(); }
    }
  }
  private receive(child: any, chunk: Buffer): void {
    if (this.child !== child) return;
    if (!this.pending || this.buffered + chunk.length > RESPONSE_CAP + 8) { this.stop('protocol'); return; }
    this.chunks.push(chunk); this.buffered += chunk.length;
    // Assemble at most one frame. No data survives to a future exchange.
    if (this.expected === null && this.buffered >= 8) {
      const joined = Buffer.concat(this.chunks, this.buffered);
      const n = joined.readBigUInt64BE();
      if (n === 0n || n > BigInt(RESPONSE_CAP)) { this.stop('protocol'); return; }
      this.expected = Number(n); this.chunks = [joined.subarray(8)]; this.buffered -= 8;
    }
    if (this.expected !== null && this.buffered >= this.expected) {
      if (this.buffered !== this.expected) { this.stop('protocol'); return; }
      const pending = this.pending; this.pending = null;
      const data = Buffer.concat(this.chunks, this.buffered);
      this.chunks = []; this.buffered = 0; this.expected = null;
      try { pending.resolve(decodeJson(data)); } catch { pending.reject(new CaviarError('protocol')); }
    }
  }
  private exchange(child: any, frame: Buffer): Promise<any> {
    return new Promise((resolve, reject) => {
      this.pending = {resolve, reject};
      child.stdin.write(frame, (error: any) => { if (error && this.child === child) this.stop('worker_failure'); });
    });
  }
  private async start(deadline: number): Promise<void> {
    if (Number(process.versions.node.split('.')[0]) < 24) fail('unsupported_target');
    if (process.platform !== 'linux' || process.arch !== 'x64') fail('unsupported_target');
    const directory = new URL('../_bin/', import.meta.url);
    const executable = fileURLToPath(new URL('caviar-redact-worker', directory));
    let manifest: any;
    try {
      const manifestPath = fileURLToPath(new URL('manifest.json', directory));
      const ms = await lstat(manifestPath);
      if (!ms.isFile() || ms.isSymbolicLink() || ms.size > 16384) fail('artifact');
      manifest = decodeJson(await readFile(manifestPath));
      const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
      const id = manifest.identity, up = manifest.upstream;
      if (!exact(id, ['protocol', 'release', 'rules', 'source', 'corpus']) || id.protocol !== 1 || pkg.name !== '@superbiche-private/caviar'
          || typeof pkg.workerRelease !== 'string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(pkg.workerRelease) || id.release !== pkg.workerRelease
          || !/^redact-v[0-9]+$/.test(id.rules) || !/^[a-f0-9]{40}$/.test(id.source) || !/^[a-f0-9]{64}$/.test(id.corpus)
          || up?.owner !== 'Caviar' || up?.source_kind !== 'git-tree' || up?.source_path !== 'redact'
          || up?.source !== id.source || up?.corpus_sha256 !== id.corpus || up?.rules !== id.rules
          || manifest.target !== 'linux/amd64' || manifest.goamd64 !== 'v1' || manifest.cgo !== false) fail('artifact');
      const stat = await lstat(executable);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size !== manifest.size || stat.size <= 0 || stat.size > (32 << 20)) fail('artifact');
      const bytes = await readFile(executable);
      if (createHash('sha256').update(bytes).digest('hex') !== manifest.sha256) fail('artifact');
    } catch (e) { if (e instanceof CaviarError && e.code === 'deadline') throw e; fail('artifact'); }
    remaining(deadline); if (this.closed) fail('closed');
    const child = spawn(executable, [], {stdio: ['pipe', 'pipe', 'ignore'], env: {GOMAXPROCS: '1'}});
    this.child = child; processes.add(child); this.generation = randomBytes(16).toString('hex'); this.seq = 0n;
    child.stdout.on('data', (data: Buffer) => this.receive(child, data));
    child.stdin.on('error', () => { if (this.child === child) this.stop('worker_failure'); });
    child.stdout.on('error', () => { if (this.child === child) this.stop('worker_failure'); });
    child.on('error', () => { if (this.child === child) this.stop('worker_failure'); });
    child.on('close', () => { child._caviarClosed = true; processes.delete(child); if (this.child === child) this.stop('worker_failure'); });
    const ready = await this.exchange(child, encode({kind: 'init', generation: this.generation, protocol: 1,
      plain: this.key === null, key: this.key === null ? null : this.key.toString('base64')}, deadline));
    if (!exact(ready, ['kind', 'generation', ...Object.keys(manifest.identity)]) || ready.kind !== 'ready'
        || ready.generation !== this.generation || Object.keys(manifest.identity).some(k => ready[k] !== manifest.identity[k])) fail('identity');
  }
  private async call(mode: string, value: unknown): Promise<Result> {
    if (process.pid !== this.owner) fail('forked_client');
    if (this.closed) fail('closed');
    if (this.busy) fail('busy');
    this.busy = true;
    const deadline = performance.now() + this.timeout * 1000;
    this.timer = setTimeout(() => this.stop(this.closed ? 'closed' : 'deadline'), this.timeout * 1000);
    try {
      const snapshot = domain(value, REQUEST_CAP, deadline);
      await this.reaping;
      remaining(deadline); if (this.closed) fail('closed');
      if (!this.child) await this.start(deadline);
      remaining(deadline); if (this.closed) fail('closed');
      const id = String(++this.seq);
      const frame = encode({kind: 'redact', generation: this.generation, id, mode, [mode === 'text' ? 'text' : 'value']: snapshot}, deadline);
      const reply = await this.exchange(this.child, frame);
      if (!reply || typeof reply !== 'object' || Array.isArray(reply)) fail('protocol');
      if (reply.kind !== 'result' || reply.generation !== this.generation || reply.id !== id) fail('protocol');
      if (exact(reply, ['kind', 'generation', 'id', 'error']) && reply.error === 'core_failure') fail('core_failure');
      if (!exact(reply, ['kind', 'generation', 'id', 'result', 'hits']) || (mode === 'text' && typeof reply.result !== 'string') || !Array.isArray(reply.hits)) fail('protocol');
      const seen = new Set();
      for (const hit of reply.hits) {
        if (!exact(hit, ['rule', 'count']) || typeof hit.rule !== 'string' || !hit.rule || !Number.isSafeInteger(hit.count) || hit.count <= 0 || seen.has(hit.rule)) fail('protocol');
        seen.add(hit.rule);
      }
      remaining(deadline); if (this.closed) fail('closed');
      return [reply.result, reply.hits];
    } catch (e) {
      const code = this.closed ? 'closed' : (e instanceof CaviarError ? e.code : 'worker_failure');
      this.stop(code); await this.reaping; throw new CaviarError(code);
    } finally { clearTimeout(this.timer); this.timer = null; this.busy = false; }
  }
}
export class Pool {
  private clients: Client[];
  private free: Client[];
  private waiters: any[] = [];
  private closed = false;
  private owner = process.pid;
  private acquireTimeout: number;
  constructor(key: Uint8Array | null, size: number, opts: PoolOptions) {
    if (!Number.isInteger(size) || size < 1 || size > 32) fail('invalid_size');
    if (!opts || typeof opts.acquireTimeout !== 'number' || !Number.isFinite(opts.acquireTimeout) || opts.acquireTimeout < 0 || opts.acquireTimeout > 60) fail('invalid_acquire_timeout');
    options(key, opts); this.acquireTimeout = opts.acquireTimeout;
    this.clients = Array.from({length: size}, () => new Client(key, opts)); this.free = [...this.clients];
  }
  string(text: string): Promise<Result<string>> { return this.dispatch('string', text) as Promise<Result<string>>; }
  value(value: Json): Promise<Result> { return this.dispatch('value', value); }
  close(): Promise<void> {
    this.closed = true; this.free = [];
    for (const waiter of this.waiters.splice(0)) { clearTimeout(waiter.timer); waiter.reject(new CaviarError('closed')); }
    return Promise.all(this.clients.map(c => c.close())).then(() => undefined);
  }
  private acquire(): Promise<Client> {
    if (process.pid !== this.owner) fail('forked_client');
    if (this.closed) fail('closed');
    const client = this.free.shift(); if (client) return Promise.resolve(client);
    if (!this.acquireTimeout) fail('busy');
    return new Promise((resolve, reject) => {
      const waiter: any = {resolve, reject, deadline: performance.now() + this.acquireTimeout * 1000};
      waiter.timer = setTimeout(() => { this.waiters = this.waiters.filter(w => w !== waiter); reject(new CaviarError(this.closed ? 'closed' : 'busy')); }, this.acquireTimeout * 1000);
      this.waiters.push(waiter);
    });
  }
  private release(client: Client): void {
    if (this.closed) return;
    while (this.waiters.length) {
      const waiter = this.waiters.shift(); clearTimeout(waiter.timer);
      if (performance.now() >= waiter.deadline) { waiter.reject(new CaviarError('busy')); continue; }
      waiter.resolve(client); return;
    }
    this.free.push(client);
  }
  private async dispatch(method: 'string' | 'value', data: any): Promise<Result> {
    const client = await this.acquire();
    try { const result = await client[method](data); if (this.closed) fail('closed'); return result; }
    catch (e) { if (this.closed) fail('closed'); throw e; }
    finally { this.release(client); }
  }
}
