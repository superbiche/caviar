#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
"""Source-only unit and declaration checks, never installed qualification."""
import os
import argparse
import hashlib
import json
from pathlib import Path
import signal
import subprocess
ROOT=Path(__file__).resolve().parents[1]

def bounded(command, env, seconds=50):
    # Reap the entire probe process group, including stopped fake/native workers.
    proc=subprocess.Popen(command,cwd=ROOT,env=env,start_new_session=True)
    try:
        rc=proc.wait(timeout=seconds)
        if rc: raise subprocess.CalledProcessError(rc,command)
    finally:
        try: os.killpg(proc.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        proc.wait()

def run(installed=False):
    node=subprocess.check_output(['node','--version'],text=True).strip()
    compiler=subprocess.check_output(['tsc','--version'],text=True).strip()
    assert node=='v24.18.1' and compiler=='Version 6.0.3','installed tooling pins; no fetch attempted'
    package=ROOT/'tmp/delivery-work/installed/node/node_modules/@superbiche-private/caviar' if installed else ROOT/'node'
    assert package.resolve()==package and (package/'lib/index.js').is_file(), 'explicit package missing or redirected'
    env=dict(os.environ,CAVIAR_NODE_PACKAGE=str(package))
    bounded(['node','--test','scripts/test_emit_node.mjs'],env)
    bounded(['node','--test','node/test/client.test.mjs'],env)
    fixture=ROOT/'node/test/types.ts'
    if installed:
        fixture=ROOT/'tmp/ts/types-installed.mts'
        fixture.parent.mkdir(parents=True,exist_ok=True)
        fixture.write_text((ROOT/'node/test/types.ts').read_text().replace("'../lib/index.js'",repr(str(package/'lib/index.js'))))
    bounded(['tsc','--noEmit','--strict','--target','es2022','--module','nodenext','--moduleResolution','nodenext',str(fixture)],env)
    if installed:
        from build_node import build
        artifact=build()
        payload={'scope':'installed','node':node,'compiler':compiler,'package_path':str(package.relative_to(ROOT)),
                 'artifact_sha256':artifact['artifact_sha256'],'lifecycle_exit':0,'types_exit':0,
                 'test_hashes':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ('node/test/client.test.mjs','node/test/types.ts','scripts/test_node.py','scripts/test_emit_node.mjs')}}
        (ROOT/'tmp/ts/installed-unit.json').write_text(json.dumps(payload,indent=2)+'\n')
    print(('Installed' if installed else 'Source')+' Node lifecycle and public declarations: PASS'+('' if installed else ' (not installed qualification)'))
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--installed',action='store_true')
    run(parser.parse_args().installed)
