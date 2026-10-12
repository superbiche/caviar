# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Michel Tomas

"""Fail-closed, synchronous client for the paired native worker."""
from .client import Client, CaviarError

__all__ = ["Client", "CaviarError"]
