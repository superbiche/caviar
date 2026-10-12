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
runtime fetch. Qualified platform scope is Linux/amd64 and CPython 3.14. A client
reuses one serial worker; concurrent calls refuse with `busy`. JS/TS bindings and
other targets are not included.

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
