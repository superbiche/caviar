# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
#!/usr/bin/env python3
"""Production gates bound to the active candidate index; no working-tree trust."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from check_hooks import verify_hook_wiring


def git(*args):
    return subprocess.check_output(["git", *args])


ROOT = Path(git("rev-parse", "--show-toplevel").decode().strip())
verify_hook_wiring(ROOT)
WORK = ROOT / "tmp/delivery-work"
WORK.mkdir(parents=True, exist_ok=True)
for directory in ("cache", "temp", "pycache"):
    (WORK / directory).mkdir(exist_ok=True)
changed = [s for s in git("diff", "--cached", "--name-only", "-z").decode().split("\0") if s]
assert changed, "empty staged candidate"
assert all(not name.startswith("tmp/") for name in changed), "private file staged"
git("diff", "--cached", "--check")
candidate = WORK / "staged-delivery"
if candidate.exists():
    shutil.rmtree(candidate)
candidate.mkdir()
snapshot = {}
for entry in git("ls-files", "--stage", "-z").decode().split("\0"):
    if not entry:
        continue
    header, name = entry.split("\t", 1)
    if name.startswith("tmp/"):
        continue
    mode, oid, stage = header.split()
    assert stage == "0" and mode in ("100644", "100755"), "conflicted/nonregular candidate"
    assert not any(p in ("__pycache__", "dist", "build", "_bin") for p in Path(name).parts), "generated file staged"
    target = candidate / name
    target.parent.mkdir(parents=True, exist_ok=True)
    data = git("cat-file", "blob", oid)
    target.write_bytes(data)
    target.chmod(0o755 if mode == "100755" else 0o644)
    snapshot[name] = hashlib.sha256(data).hexdigest()
for policy in ("hooks/pre-commit", "scripts/commit_gate.py", "scripts/check_hooks.py"):
    assert (candidate / policy).read_bytes() == (ROOT / policy).read_bytes(), "executed hook differs from index"
assert (candidate / "hooks/pre-commit").stat().st_mode & 0o111, "candidate hook not executable"
# The owned source tree and encoded fixtures are exact staged inputs. Match the actual index's subtree identity as well.
pins = json.loads((candidate / "docs/UPSTREAM.json").read_text())
assert git("rev-parse", git("write-tree").decode().strip() + ":redact").decode().strip() == pins["source"], "index source identity mismatch"
env = dict(os.environ, GOCACHE=str(WORK / "cache"), GOTMPDIR=str(WORK / "temp"),
           TMPDIR=str(WORK / "temp"), PYTHONPYCACHEPREFIX=str(WORK / "pycache"),
           GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local",
           PYTHONPATH=os.pathsep.join(str(candidate / p) for p in ("python", "scripts", ".")), SOURCE_DATE_EPOCH="1791576000")
receipts = {"hook_wiring": "PASS", "index_whitespace": "PASS"}
commands = [("contract_inputs", ["python3", "scripts/prepare.py"]),
            ("provenance", ["python3", "scripts/check_provenance.py"]),
            ("go_tests", ["go", "test", "./..."]),
            ("go_vet", ["go", "vet", "./..."]),
            ("hook_syntax", ["bash", "-n", "hooks/pre-commit"]),
            ("wheel_build", ["python3", "scripts/build.py"]),
            ("lifecycle", ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"])]
for label, command in commands:
    with (WORK / ("hook-" + label + ".log")).open("w") as log:
        completed = subprocess.run(command, cwd=candidate, env=env, stdout=log, stderr=subprocess.STDOUT)
    if completed.returncode:
        raise SystemExit(label + " failed; private log under tmp/delivery-work")
    receipts[label] = "PASS"
    print(label + ": PASS", flush=True)
assert not subprocess.check_output(["gofmt", "-l", "cmd", "internal", "redact"], cwd=candidate), "Go format drift"
receipts["go_format"] = "PASS"
# The exact candidate's installed qualification is retained and bound to the
# client/core artifact; this gate checks the sealed evidence, not a bypass.
subprocess.run(["python3", "scripts/check_qualification.py"], cwd=candidate, env=env, check=True)
receipts["installed_qualification"] = "PASS"
subprocess.run(["python3", "scripts/check_differential.py"], cwd=candidate, env=env, check=True)
receipts["installed_differential"] = "PASS"
scan_tree = WORK / "scan-delivery"
if scan_tree.exists():
    shutil.rmtree(scan_tree)
scan_tree.mkdir()
for name in snapshot:
    target = scan_tree / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(candidate / name, target)
with (WORK / "hook-secrets.jsonl").open("w") as out, (WORK / "hook-secrets.stderr").open("w") as err:
    scan = subprocess.run(["trufflehog", "filesystem", "--no-update", "--no-verification", "--fail",
                           "--fail-on-scan-errors", "--json", str(scan_tree)], stdout=out, stderr=err, env=env)
if scan.returncode:
    raise SystemExit("Secret scan failed; contents withheld")
receipts["secret_scan"] = "PASS"
for name, expected in snapshot.items():
    assert hashlib.sha256((candidate / name).read_bytes()).hexdigest() == expected, "gate changed candidate"
(WORK / "precommit-receipt.json").write_text(json.dumps({"candidate_tree": git("write-tree").decode().strip(),
    "staged_paths": changed, "gates": receipts}, indent=2) + "\n")
print("Exact index delivery gates: PASS", flush=True)
