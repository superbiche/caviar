#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Offline local wheel build using the installed exact-pinned backend."""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import tomllib
import subprocess
import sys
import shutil
from provenance import verify

ROOT = Path(__file__).resolve().parents[1]


def build():
    os.chdir(ROOT)
    os.environ.setdefault("SOURCE_DATE_EPOCH", "1791576000")
    if importlib.metadata.version("setuptools") != "80.10.2":
        raise SystemExit("Installed build backend must be setuptools 80.10.2; no fetch attempted")
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise SystemExit("Only qualified Linux/amd64 builds are supported")
    from prepare import prepare
    prepare()
    provenance = verify()
    for name, expected in provenance["runtime_files"].items():
        if hashlib.sha256((ROOT / "redact" / name).read_bytes()).hexdigest() != expected:
            raise SystemExit("Upstream runtime hash mismatch")
    declared_rules = re.search(r'const RulesVersion = "([^"\n]+)"', (ROOT / "redact/redact.go").read_text())
    if declared_rules is None or declared_rules.group(1) != provenance["rules"]:
        raise SystemExit("RulesVersion does not match the pinned input")
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    identity = {"protocol": 1, "release": project["version"], "rules": provenance["rules"],
                "source": provenance["source"], "corpus": provenance["corpus_sha256"]}
    work = ROOT / "tmp/delivery-work"
    for name in ("cache", "temp", "pycache"):
        (work / name).mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ, GOCACHE=str(work / "cache"), GOTMPDIR=str(work / "temp"),
                       GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local",
                       CGO_ENABLED="0", GOOS="linux", GOARCH="amd64", GOAMD64="v1")
    # Safe audits the current module tree. Keep historical experiments/caches
    # outside the actual build input; the gate is unchanged and still runs.
    build_source = work / "worker-build-source"
    if build_source.exists():
        shutil.rmtree(build_source)
    build_source.mkdir()
    shutil.copyfile(ROOT / "go.mod", build_source / "go.mod")
    for name in ("cmd", "internal"):
        shutil.copytree(ROOT / name, build_source / name)
    (build_source / "redact").mkdir()
    for name in provenance["runtime_files"]:
        shutil.copyfile(ROOT / "redact" / name, build_source / "redact" / name)
    compiler = subprocess.check_output(["go", "version"], cwd=build_source, env=environment, text=True).strip()
    if compiler != "go version go1.26.9-X:nodwarf5 linux/amd64":
        raise SystemExit("Installed Go compiler must be 1.26.9; no fetch attempted")
    destination = ROOT / "python/caviar_redact/_bin"
    destination.mkdir(parents=True, exist_ok=True)
    worker = destination / "caviar-redact-worker"
    subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -X main.release=" + identity["release"] +
                    " -X main.source=" + identity["source"] + " -X main.corpus=" + identity["corpus"],
                    "-o", str(worker), "./cmd/redact-worker"], cwd=build_source, env=environment, check=True)
    worker.chmod(0o755)
    manifest = {"identity": identity, "target": "linux/amd64", "goamd64": "v1",
                "compiler": compiler, "cgo": False, "size": worker.stat().st_size,
                "sha256": hashlib.sha256(worker.read_bytes()).hexdigest(),
                "upstream": provenance}
    (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    from setuptools.build_meta import build_wheel
    result = build_wheel(str(ROOT / "dist"))
    wheel = ROOT / "dist" / result
    print(json.dumps({"wheel": str(wheel), "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                      "worker_sha256": manifest["sha256"]}))


if __name__ == "__main__":
    build()
    from build_node import build as build_node_package
    build_node_package()
