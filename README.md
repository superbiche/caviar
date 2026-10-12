# Caviar

Caviar provides a deterministic Go redaction core and a Python client with a
supervised native worker. Its versioned rule table is redact-v7.

Each trust domain supplies its own HMAC key. Calls fail closed: callers must
abort persistence or export on any redaction error. Redaction uses explicit
secret patterns; it cannot detect every possible credential.

```go
import "github.com/superbiche/caviar/redact"

filter := redact.New(key)
clean, hits, err := filter.String(text)
// Abort persistence/export when err != nil.
```

```python
from caviar_redact import Client, CaviarError

with Client(key, timeout=5.0) as filter:
    clean, hits = filter.string(text)
# CaviarError must abort persistence/export; never fall back to text.
```

The wheel contains its static worker: consumers need no Go installation and no
runtime fetch. Qualified platform scope is Linux/amd64 and CPython 3.12, 3.13 and 3.14. A client
reuses one serial worker; concurrent calls refuse with `busy`. JS/TS bindings and
other targets are not included.

For concurrency, a `Pool` owns N clients, each with its own worker process and
its own copy of the trust domain key. Each client still admits one call at a
time; the pool admits up to N concurrent calls and, when every worker is busy,
waits for one to free up to a bounded `acquire_timeout` before refusing with
`busy`. The client deadline starts when a call is admitted, so the worst case
is `acquire_timeout + timeout`. A failed call returns its client to the pool (it
restarts its worker on next use); a call is never retried on another worker.
`close()` is terminal: it never waits for in-flight calls, closes every client,
releases admission waiters with `closed`, and later calls raise `closed`. In a
forked child, calls refuse with `forked_client`, and `close()` disposes of only
that process's pipe copies without blocking or touching the parent's workers.

```python
from caviar_redact import Pool, CaviarError

with Pool(key, 2, acquire_timeout=5.0) as pool:
    clean, hits = pool.string(text)
    # Up to 2 calls run at once; the 3rd waits up to 5 s, then raises busy.
# CaviarError must abort persistence/export; never fall back to text.
```

For `value()`, keep the entire caller-owned input tree unchanged until the call
returns. Concurrent mutation can invalidate type, request-size and memory bounds;
synchronize access or pass a stable private copy.

Release wheels are distributed as one GitHub release asset plus a byte-identical
Forgejo package mirror. Consumers install the exact version and independently
verified SHA-256 through their package policy. There is no public PyPI distribution.
Each release supplies its reviewed download hash.

See [protocol](docs/PROTOCOL.md), [development](docs/DEVELOPMENT.md),
[security](docs/SECURITY.md) and [changelog](CHANGELOG.md).
Licensed AGPL-3.0-only. Original copyright notices are preserved.
