#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
"""Bind complete installed Node qualification to the rebuilt package members."""
import hashlib
import json
from pathlib import Path
import statistics
from build_node import build
ROOT=Path(__file__).resolve().parents[1]

def verify():
    artifact=build()
    receipt_path=ROOT/'docs/node-results.json'
    assert receipt_path.is_file(), 'Installed Node qualification pending: docs/node-results.json missing'
    receipt=json.loads(receipt_path.read_text())
    assert receipt['artifact_sha256']==artifact['artifact_sha256']
    assert receipt['members']==artifact['members']
    for name, expected in receipt['test_hashes'].items():
        assert name in ('node/test/client.test.mjs', 'node/test/types.ts', 'scripts/test_node.py','scripts/test_emit_node.mjs')
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==expected
    assert set(receipt['test_hashes'])=={'node/test/client.test.mjs','node/test/types.ts','scripts/test_node.py','scripts/test_emit_node.mjs'}
    pins=json.loads((ROOT/'docs/UPSTREAM.json').read_text())
    from prepare import prepare
    prepare()
    from campaign_inputs import materialize
    perf={}
    for line in (ROOT/pins['corpus_fixture']).read_text().splitlines():
        row=json.loads(line)
        if row['tier']=='perf':
            for mode in (['text','value'] if row.get('structured') else ['text']):
                for keyed in (False,True):
                    perf[(row['id'],mode,keyed)]=(row['max_ms'],len(materialize(row).encode()))
    canonical=json.loads((ROOT/'docs/compatibility-results.json').read_text())['current_oracles']
    for kind,count in [('corpus',1336),('differential',40000)]:
        filename='docs/node-'+kind+'.json';raw=(ROOT/filename).read_bytes()
        assert hashlib.sha256(raw).hexdigest()==receipt['qualification'][kind]['sha256']
        q=json.loads(raw)
        assert q['qualification_generator_sha256']==hashlib.sha256((ROOT/'scripts/qualify_node.mjs').read_bytes()).hexdigest()
        assert q['node']=='v24.18.1' and q['comparisons']==count and not q['mismatches']
        assert q['artifact_hashes']==artifact['members']
        assert q['package_name']==artifact['package_name'] and q['package_version']==artifact['version'] and q['worker_release']==artifact['worker_release']
        assert q['identity']=={'protocol':1,'release':artifact['worker_release'],'source':pins['source'],'rules':pins['rules'],'corpus':pins['corpus_sha256']}
        assert q['package_path']=='tmp/delivery-work/installed/node/node_modules/@superbiche-private/caviar'
        assert q['oracle']['reference_sha256']==pins['reference_sha256'] and q['oracle']['corpus_sha256']==pins['corpus_sha256']
        assert q['oracle']['generator_sha256']==hashlib.sha256((ROOT/'scripts/campaign_inputs.py').read_bytes()).hexdigest()
        assert q['oracle']['oracle_python'].startswith('3.14.') and q['oracle']['oracle_implementation']=='cpython'
        assert q['oracle']['records']==count and q['oracle']['kind']==kind
        assert q['oracle']==canonical[kind]
        if kind=='corpus':
            rows=q['p4_rows'];assert len(rows)==326 and q['samples_per_row']==30 and q['warmups']==1 and not q['p4_over_budget']
            assert {(r['id'],r['mode'],r['keyed']) for r in rows}==set(perf)
            assert all((r['max_ms'],r['bytes'])==perf[(r['id'],r['mode'],r['keyed'])] for r in rows)
            assert all(len(r['samples_ms'])==30 and statistics.median(r['samples_ms'])==r['median_ms'] and 0<=r['median_ms']<=r['max_ms'] and r['ratio']==r['median_ms']/r['max_ms'] for r in rows)
        else: assert q['seed']==0xCA6106 and q['cases']==10000
    assert receipt['lifecycle']['exit']==receipt['types']['exit']==0
    assert receipt['lifecycle']['package_path']==receipt['types']['package_path']=='tmp/delivery-work/installed/node/node_modules/@superbiche-private/caviar'
    assert receipt['lifecycle']['artifact_sha256']==receipt['types']['artifact_sha256']==artifact['artifact_sha256']
    print('Exact installed Node corpus/P4/differential and artifact binding: PASS')
if __name__=='__main__': verify()
