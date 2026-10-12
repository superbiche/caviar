# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Verify self-owned source identity without a circular future commit pin."""
import gzip
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def git_object(kind, data):
    return hashlib.sha1(kind.encode() + b" " + str(len(data)).encode() + b"\0" + data).digest()


def source_tree(directory):
    """Git tree identity of regular source files; reject undeclared extra files."""
    entries = []
    for path in directory.iterdir():
        if path.is_symlink():
            raise ValueError("source symlink")
        if path.is_dir():
            entries.append((path.name + "/", b"40000 " + path.name.encode() + b"\0" + bytes.fromhex(source_tree(path))))
        else:
            mode = b"100755" if path.stat().st_mode & 0o111 else b"100644"
            entries.append((path.name, mode + b" " + path.name.encode() + b"\0" + git_object("blob", path.read_bytes())))
    return git_object("tree", b"".join(data for _, data in sorted(entries))).hex()


def verify(root=ROOT):
    pins = json.loads((root / "docs/UPSTREAM.json").read_text())
    assert pins["owner"] == "Caviar" and pins["source_kind"] == "git-tree" and pins["source_path"] == "redact"
    module = re.search(r"^module ([^\s]+)$", (root / "go.mod").read_text(), re.MULTILINE)
    assert module and module.group(1) == pins["module"] == "github.com/superbiche/caviar", "module identity mismatch"
    assert re.fullmatch(r"[0-9a-f]{40}", pins["source"])
    assert source_tree(root / pins["source_path"]) == pins["source"], "source tree mismatch"
    for name, expected in pins["runtime_files"].items():
        assert hashlib.sha256((root / "redact" / name).read_bytes()).hexdigest() == expected, "runtime provenance mismatch"
    assert hashlib.sha256((root / "LICENSE").read_bytes()).hexdigest() == pins["license_sha256"], "license mismatch"
    try:
        from .fixtures import verify as verify_fixture
    except ImportError:
        from fixtures import verify as verify_fixture
    for name, pin in (("corpus", "corpus_sha256"), ("reference", "reference_sha256")):
        metadata = json.loads((root / ("fixtures/redact-v7." + name + ".manifest.json")).read_text())
        raw = verify_fixture(root / ("fixtures/redact-v7." + name + ".b85"), metadata)
        assert hashlib.sha256(raw).hexdigest() == pins[pin], "published input mismatch"
    match = re.search(r'const RulesVersion = "([^"\n]+)"', (root / "redact/redact.go").read_text())
    assert match and match.group(1) == pins["rules"], "RulesVersion mismatch"
    return pins
