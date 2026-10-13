// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
if (process.version !== 'v24.18.1') throw new Error('Build requires installed Node 24.18.1; no fetch attempted');
mkdirSync('node/lib', {recursive: true});
const source = readFileSync('node/src/index.ts', 'utf8');
// Strip mode preserves positions by filling erased declarations with spaces.
// Remove only wholly erased lines; never trim original string/template content.
const originalLines = source.split('\n');
const strippedLines = stripTypeScriptTypes(source, {mode: 'strip'}).split('\n');
if (originalLines.length !== strippedLines.length) throw new Error('Type eraser changed line positions');
const emitted = strippedLines.map((line, index) => {
  if (/^[ \t]+$/.test(line) && line !== originalLines[index]) return '';
  if (/[ \t]+$/.test(line)) throw new Error('Source trailing whitespace cannot be trimmed safely');
  return line;
}).join('\n');
writeFileSync('node/lib/index.js', emitted);
writeFileSync('node/lib/index.d.ts', readFileSync('node/types/index.d.ts'));
