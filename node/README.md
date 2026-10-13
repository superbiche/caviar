# Caviar for Node and TypeScript

The local `@superbiche-private/caviar` 0.4.0 package supports Node >=24 on Linux/x64,
qualified on Node 24.18.1. It embeds exactly the static worker and manifest
from the qualified Python 0.4.0 wheel, uses no runtime npm dependencies, and
implements the same [framed protocol](../docs/PROTOCOL.md). No rule port or
fallback redactor is included. Public npm publication is not part of this slice.

```ts
import { Client, Pool, CaviarError } from '@superbiche-private/caviar';
// key is owned and supplied by this consumer, never a shared fleet HMAC key.
const client = new Client(key, { timeout: 5 });
try {
  const [result, hits] = await client.string(text);
  // Persist only a successful result. Abort persistence/export on any error.
} finally {
  await client.close();
}
const pool = new Pool(key, 2, { acquireTimeout: 0.25, timeout: 5 });
try { const [result, hits] = await pool.value(stableJson); }
finally { await pool.close(); }
```

`key` is Uint8Array (Buffer accepted), 16–65,536 bytes, privately copied.
Plain mode requires `new Client(null, {allowPlain: true})` (same Pool option).
Timeouts are seconds: request timeout >0 and <=60, default 5; acquisition
0..60; Pool size integer 1..32. Client overlap refuses `busy`; a Pool admits up
to its size and then waits at most acquireTimeout. The request deadline starts
at admission. Failure is never replayed on another worker. Error objects expose
only a stable `CaviarError.code`, never caller content, keys or stderr.

Close is terminal and immediately kills owned workers and releases waiters;
its Promise resolves after child reaping, without waiting for an in-flight
request lock. A failed generation is killed and reaped before reuse. The next
call may start a fresh worker. Idle child/stdio handles are unref'd so an unclosed Client permits natural process
exit; normal exit kills owned workers. Active calls and reaping keep the loop alive. SIGKILL
of the host cannot run JavaScript cleanup and is not covered by that guarantee.
Node child_process.fork starts a fresh runtime, not a heap copy like POSIX fork;
Client objects are not transferable across process or worker-thread boundaries.

Requests are capped at 2 MiB JSON, responses at 8 MiB. Domain validation caps
aggregate expansion and depth 500. `value` accepts JSON primitives, dense
arrays and plain data objects. Use BigInt for integers outside the safe Number
range; unsafe integer Numbers, NaN/infinities, getters, proxies, custom objects,
cycles, malformed Unicode and unsupported types refuse. Results use Number for
safe integers and BigInt for larger integer tokens. Do not JSON.stringify a
BigInt result without your own lossless serialization policy. Client input is
snapshotted before the first asynchronous yield. Pool snapshots after admission;
callers must keep input unchanged until the operation returns, including while
waiting for admission (the protocol's caller-value stability precondition).
Getters/toJSON are never run.

The encompassing monotonic deadline covers validation, artifact verification,
initialization, serialization, pipe I/O and response checks. Expiry kills the
worker with SIGKILL. Node timer scheduling depends on the event loop: blocking
caller JavaScript can delay the kill callback; it cannot make an expired result
succeed, because completion checks the monotonic deadline. Keep the event loop
responsive. Pool acquisition has the same scheduling limitation. Earlier Node
versions and other OS/architectures are unqualified.

The package verifies worker type, size, SHA256, identity and every ready field
before redacting; no configurable executable or environment key delivery exists.
Keep the installed package and its parent directories trusted and immutable;
hash verification does not defend against a concurrent local filesystem writer.

License: AGPL-3.0-only. Go runtime notices are included in the artifact.
`src/index.ts` ships as the preferred form for modification under AGPL, not as a
runtime dependency. `decodeJson` is a declared @internal protocol tooling hook;
consumer APIs are Client, Pool and CaviarError.

The npm version is independent of `workerRelease: "0.4.0"` in package metadata.
The bundled worker and wire ready identity remain pinned to the qualified
0.4.0 manifest. Stable consumer adoption requires installed qualification and
the promotion delta review.
