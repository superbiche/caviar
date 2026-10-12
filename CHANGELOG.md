# Changelog

## 0.3.1

- Qualify the installed Python binding on CPython 3.12, 3.13 and 3.14.
- Keep the canonical public-reference oracle on CPython 3.14 for each target.
- Preserve the redact-v7 core, protocol, key custody and fail-closed semantics.

## 0.3.0

- First public module identity: `github.com/superbiche/caviar`.
- Port redact-v7: code-cased bare assignment decisions, command-bounded,
  case-sensitive mysql `-p` scanning, and shallower-quote stops for P1 values.
- Ship synthetic corpus and Python oracle as keyless lossless fixtures, with
  published decoded hashes and offline materialization into ignored `tmp/`.
- Retain the serial fail-closed worker and Python client, with caller-owned keys.
