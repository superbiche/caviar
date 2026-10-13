// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {resolve} from 'node:path';
const emitter = resolve('scripts/emit_node.mjs');
function fixture(source, check) {
  mkdirSync('tmp/ts', {recursive: true});
  const cwd = mkdtempSync('tmp/ts/emitter-');
  try {
    mkdirSync(cwd+'/node/src', {recursive: true});
    mkdirSync(cwd+'/node/types', {recursive: true});
    writeFileSync(cwd+'/node/src/index.ts', source);
    writeFileSync(cwd+'/node/types/index.d.ts', 'export {};\n');
    check(cwd, () => execFileSync(process.execPath, [emitter], {cwd, timeout:10000, stdio:'pipe'}));
  } finally {rmSync(cwd, {recursive:true, force:true});}
}
test('erased type lines are empty; runtime literals remain byte-identical', () => {
  const runtime = 'const quoted = "keep  ";\nconst escaped = "quote\\\"  ";\nconst template = `first\\t  \\nsecond`;\n';
  fixture('export type Example = { value: string };\n'+runtime, (cwd, emit) => {
    emit();
    const output = readFileSync(cwd+'/node/lib/index.js', 'utf8');
    assert.equal(output, '\n'+runtime);
    assert.equal(/[ \t]+$/m.test(output), false);
  });
});
test('trailing whitespace inside a multiline literal refuses without trimming', () => {
  fixture('const template = `first\n  \nlast`;\n', (cwd, emit) => {
    assert.throws(emit, error => error.status === 1 && error.stderr.toString().includes('cannot be trimmed safely'));
    assert.equal(existsSync(cwd+'/node/lib/index.js'), false);
  });
});
test('source trailing whitespace refuses before writing generated JS', () => {
  fixture('const ordinary = "keep  ";  \n', (cwd, emit) => {
    assert.throws(emit, error => error.status === 1 && error.stderr.toString().includes('cannot be trimmed safely'));
    assert.equal(existsSync(cwd+'/node/lib/index.js'), false);
  });
});
