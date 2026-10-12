# Development

The public inputs are lossless gzip plus canonical Base85. Encoding is not
confidentiality. The manifest pins encoded and decoded bytes, size and line
count. No key, CI secret or network call is required. Generate plaintext only
under ignored `tmp/`:

```sh
python3 scripts/prepare.py
```

This materializes the 598-seed redact-v7 corpus and its Python reference. An
existing altered output, invalid hash, gzip header fields, extra member,
noncanonical encoding, excessive size, traversal or symlink refuses. Never
commit plaintext or print fixture values.

Native gates use the complete corpus, including every perf seed (median of 30
calls after warmup). Installed qualification covers 1,336 comparisons in
plain/keyed text/structured modes and 326 full-route P4 rows. The deterministic
differential campaign uses seed `0xCA6106`, 10,000 cases and 40,000 comparisons.

The offline build requires the exact installed Go 1.26.9-X:nodwarf5 Linux/amd64
compiler and setuptools 80.10.2. Install tools only through your package policy
at exact versions. The project never fetches build dependencies itself.

```sh
python3 scripts/build.py
```

The resulting platform wheel includes the static worker and its identity
manifest. A second isolated build must produce identical wheel bytes. Full
binding qualification runs against an installed wheel, never a source-tree
client import. Its evidence is bound to the exact client, manifest, worker,
corpus and oracle. Installation is a separate authorized package operation.

Before any commit, bootstrap repository-local hooks:

```sh
git config --local core.hooksPath hooks
```

Clones do not inherit that local Git setting. The gate refuses an effective
hooks path other than `hooks`. Source and encoded fixtures must pass the real
TruffleHog scan with no exclusions; GitHub push protection is an additional
publication gate. A refusal stops publication, with no waiver.

Release qualification results bind the exact worker/client, full core-tree
identity, corpus and reference. A changed payload requires new installed-route
qualification; old receipts do not qualify new bytes. Release assets and their
mirrors must match the reviewed wheel hash. The repository's private
vulnerability reporting channel must be enabled before a public push or tag.

## Python compatibility qualification

Build with the qualified CPython 3.14 backend. The immutable 0.4.0 wheel supports
CPython 3.12, 3.13 and 3.14 on Linux/amd64. `make build` performs the offline
build; `make test` prepares the pinned fixtures, verifies provenance, runs
`go test` and `go vet`, and runs unittest discovery using `PYTHON` and the
caller-selected installed binding path.

Generate canonical corpus and differential expectations once under CPython
3.14 with `scripts/canonical_results.py`. Their metadata binds runtime,
reference/corpus pins, generator and output hashes. Expected payloads are
ignored test artifacts, never public fixtures or log output. Each target minor
runs `scripts/qualify_compat.py` against its installed wheel and these same
expectations. No reference is imported into the target interpreter; oracle
preparation and parsing stay outside full-route P4 timings.

Each minor needs its own lifecycle, 1,336 parity, 326 P4 and 40,000 differential
comparison receipts. Do not lower Requires-Python on the existing 0.3.0 wheel
or advertise a target that failed qualification. Publication needs independent
review and its own approval; consumer adoption remains separately owned.

Canonical preparation (CPython 3.14 only):

```sh
python3.14 scripts/canonical_results.py --kind corpus --output tmp/oracle/corpus.jsonl
python3.14 scripts/canonical_results.py --kind differential --output tmp/oracle/differential.jsonl
```

The files use exclusive creation. Preserve their `.meta.json` files and exact
hashes; a partial run must be removed deliberately before a new preparation.
For each minor, select the installed wheel through `PYTHONPATH` and run both
campaigns. For example, with the installed target `compat-040`:

```sh
PYTHONPATH=tmp/delivery-work/installed/compat-040 python3.12 scripts/qualify_compat.py \
  --oracle tmp/oracle/corpus.jsonl --output tmp/qualification-3.12.json
PYTHONPATH=tmp/delivery-work/installed/compat-040 python3.12 scripts/qualify_compat.py \
  --oracle tmp/oracle/differential.jsonl --output tmp/differential-3.12.json
```

Repeat with CPython 3.13 and 3.14 and distinct result paths. Oracle input/output
records are streamed with a 16 MiB per-record limit; no expectation is printed.
The commit gate additionally checks the retained three-minor compatibility
matrix. Legacy direct-reference scripts refuse non-3.14 interpreters.

The retained compatibility receipts carry predecessor generator SHA256
`919895a8c1041ce1d1d0195ef7072521a29bbe52e85aa4b742d80ed0cc962dca`
from measurement before a trailing-newline fix; the regenerated expectation
streams are byte-identical.
