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
