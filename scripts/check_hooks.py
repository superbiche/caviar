# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas
#!/usr/bin/env python3
"""Refuse missing clone bootstrap or an overridden required hooks path."""
from pathlib import Path
import os
import subprocess


def verify_hook_wiring(root):
    for scope in ([], ["--local"]):
        result = subprocess.run(["git", "-C", str(root), "config", *scope,
                                 "--get", "core.hooksPath"],
                                capture_output=True, text=True, check=False)
        if result.returncode != 0 or result.stdout.strip() != "hooks":
            raise RuntimeError("Required hooks path is hooks; run git config --local core.hooksPath hooks and remove overrides")
    if not os.access(Path(root) / "hooks/pre-commit", os.X_OK):
        raise RuntimeError("Required hooks/pre-commit is missing or not executable")


if __name__ == "__main__":
    verify_hook_wiring(Path(__file__).resolve().parents[1])
    print("Hook wiring: PASS")
