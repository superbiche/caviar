#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
"""Deterministic dependency-free Node archive using the exact wheel payload."""
import gzip
import hashlib
import io
import json
import re
from pathlib import Path
import subprocess
import tarfile
import zipfile
import tomllib
ROOT = Path(__file__).resolve().parents[1]

def build():
    subprocess.run(['node', 'scripts/emit_node.mjs'], cwd=ROOT, check=True)
    package = json.loads((ROOT / 'node/package.json').read_text())
    version = tomllib.loads((ROOT / 'pyproject.toml').read_text())['project']['version']
    assert package['name'] == '@superbiche-private/caviar'
    assert package['workerRelease'] == version and package['engines'] == {'node': '>=24'}
    package_version = package['version']
    assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', package_version)
    assert not any(k in package for k in ('dependencies', 'optionalDependencies', 'scripts'))
    wheel = ROOT / ('dist/caviar_redact-' + version + '-py3-none-linux_x86_64.whl')
    with zipfile.ZipFile(wheel) as z:
        prefix = 'caviar_redact-' + version + '.data/purelib/caviar_redact/_bin/'
        worker = z.read(prefix + 'caviar-redact-worker')
        manifest = z.read(prefix + 'manifest.json')
    source_bin = ROOT / 'node/_bin'
    source_bin.mkdir(parents=True, exist_ok=True)
    (source_bin / 'caviar-redact-worker').write_bytes(worker)
    (source_bin / 'caviar-redact-worker').chmod(0o755)
    (source_bin / 'manifest.json').write_bytes(manifest)
    pins = json.loads(manifest)
    assert hashlib.sha256(worker).hexdigest() == pins['sha256'] and len(worker) == pins['size']
    assert pins['identity']['release'] == version
    members = {n: (ROOT / p).read_bytes() for n, p in {
        'package.json': 'node/package.json', 'README.md': 'node/README.md',
        'LICENSE': 'LICENSE', 'THIRD-PARTY-NOTICES.md': 'docs/THIRD-PARTY-NOTICES.md',
        'lib/index.js': 'node/lib/index.js', 'lib/index.d.ts': 'node/lib/index.d.ts',
        'src/index.ts': 'node/src/index.ts',
    }.items()}
    members.update({'_bin/caviar-redact-worker': worker, '_bin/manifest.json': manifest})
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w', format=tarfile.GNU_FORMAT) as archive:
        for name in sorted(members):
            info = tarfile.TarInfo('package/' + name)
            info.size = len(members[name]); info.mtime = 1791576000
            info.mode = 0o755 if name.endswith('caviar-redact-worker') else 0o644
            archive.addfile(info, io.BytesIO(members[name]))
    artifact = ROOT / ('dist/superbiche-private-caviar-' + package_version + '.tgz')
    with artifact.open('wb') as out, gzip.GzipFile(filename='', mode='wb', fileobj=out, mtime=0) as compressed:
        compressed.write(payload.getvalue())
    receipt = {'package_name': package['name'], 'artifact_file': artifact.name, 'version': package_version, 'worker_release': version, 'node': 'v24.18.1', 'artifact_sha256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
               'worker_sha256': pins['sha256'], 'manifest_sha256': hashlib.sha256(manifest).hexdigest(),
               'members': {n: hashlib.sha256(b).hexdigest() for n, b in members.items()}}
    work = ROOT / 'tmp/ts'; work.mkdir(parents=True, exist_ok=True)
    (work / 'build.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps({'artifact': artifact.name, 'sha256': receipt['artifact_sha256']}))
    return receipt

if __name__ == '__main__': build()
