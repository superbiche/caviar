#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
"""Assemble genuine installed receipts; no placeholder, mutation or path repair."""
import hashlib
import json
from pathlib import Path
from build_node import build
ROOT=Path(__file__).resolve().parents[1]
artifact=build()
unit=json.loads((ROOT/'tmp/ts/installed-unit.json').read_text())
assert unit['scope']=='installed' and unit['lifecycle_exit']==unit['types_exit']==0
assert unit['artifact_sha256']==artifact['artifact_sha256']
expected='tmp/delivery-work/installed/node/node_modules/@superbiche-private/caviar'
assert unit['package_path']==expected
installed=ROOT/expected
assert installed.resolve()==installed
for name,pin in artifact['members'].items():
    assert hashlib.sha256((installed/name).read_bytes()).hexdigest()==pin,'installed bytes differ from rebuilt archive'
qualification={}
for kind in ('corpus','differential'):
    path=ROOT/('docs/node-'+kind+'.json')
    q=json.loads(path.read_bytes())
    assert q['package_path']==expected and q['artifact_hashes']==artifact['members']
    qualification[kind]={'path':str(path.relative_to(ROOT)),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
receipt={**artifact,'qualification':qualification,'test_hashes':unit['test_hashes']}
for name in ('lifecycle','types'):
    receipt[name]={'exit':0,'package_path':expected,'artifact_sha256':artifact['artifact_sha256']}
(ROOT/'docs/node-results.json').write_text(json.dumps(receipt,indent=2)+'\n')
from check_node import verify
verify()
