# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

#!/usr/bin/env python3
"""Mechanical runtime/source/license pins; no fixture values are emitted."""
from provenance import verify

verify()
print("Self-owned source tree, corpus and license pins: PASS")
