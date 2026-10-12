# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Source-tree identity agrees with Git, including modes and directory order."""
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest

from scripts.provenance import source_tree, verify


class ProvenanceTests(unittest.TestCase):
    def test_module_identity_tamper_is_refused(self):
        root = Path(__file__).resolve().parents[1]
        work = root / "tmp/delivery-work/test-provenance"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            candidate = Path(temporary)
            for name in ("go.mod", "LICENSE", "docs/UPSTREAM.json"):
                target = candidate / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(root / name, target)
            shutil.copytree(root / "redact", candidate / "redact")
            shutil.copytree(root / "fixtures", candidate / "fixtures")
            verify(candidate)
            (candidate / "go.mod").write_text("module synthetic.invalid/other\n\ngo 1.25.0\n")
            with self.assertRaisesRegex(AssertionError, "module identity mismatch"):
                verify(candidate)

    def test_source_identity_matches_git_tree(self):
        root = Path.cwd() / "tmp/delivery-work/test-provenance"
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            repo = Path(temporary)
            core = repo / "core"
            (core / "a").mkdir(parents=True)
            (core / "a/z.go").write_text("synthetic source\n")
            (core / "a.go").write_text("synthetic sibling\n")
            executable = core / "tool"
            executable.write_text("synthetic executable\n")
            executable.chmod(0o755)
            subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
            subprocess.run(["git", "-C", str(repo), "add", "--", "core"], check=True)
            tree = subprocess.check_output(["git", "-C", str(repo), "write-tree"], text=True).strip()
            expected = subprocess.check_output(["git", "-C", str(repo), "rev-parse", tree + ":core"], text=True).strip()
            self.assertEqual(source_tree(core), expected)
            executable.chmod(0o644)
            self.assertNotEqual(source_tree(core), expected)
            (core / "a.go").write_text("modified source\n")
            self.assertNotEqual(source_tree(core), expected)

    def test_source_symlink_is_refused(self):
        root = Path.cwd() / "tmp/delivery-work/test-provenance"
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            core = Path(temporary)
            (core / "source").write_text("synthetic source\n")
            (core / "link").symlink_to("source")
            with self.assertRaisesRegex(ValueError, "source symlink"):
                source_tree(core)
