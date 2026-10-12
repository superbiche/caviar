# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Clone bootstrap and effective Git overrides must fail closed."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.check_hooks import verify_hook_wiring


class HookWiringTests(unittest.TestCase):
    def test_clone_bootstrap_and_refusals(self):
        work = Path(__file__).resolve().parents[1] / "tmp/delivery-work/test-hooks"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=work) as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            hook = root / "hooks/pre-commit"
            hook.parent.mkdir()
            hook.write_text("#!/bin/sh\nexit 0\n")
            hook.chmod(0o755)
            for value in (None, "other-hooks"):
                if value is not None:
                    subprocess.run(["git", "-C", str(root), "config", "--local",
                                    "core.hooksPath", value], check=True)
                with self.assertRaisesRegex(RuntimeError, "Required hooks path"):
                    verify_hook_wiring(root)
            subprocess.run(["git", "-C", str(root), "config", "--local",
                            "core.hooksPath", "hooks"], check=True)
            verify_hook_wiring(root)
            with patch.dict(os.environ, {"GIT_CONFIG_COUNT": "1",
                                         "GIT_CONFIG_KEY_0": "core.hooksPath",
                                         "GIT_CONFIG_VALUE_0": "other-hooks"}):
                with self.assertRaisesRegex(RuntimeError, "Required hooks path"):
                    verify_hook_wiring(root)
            hook.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, "not executable"):
                verify_hook_wiring(root)
