# Worker protocol

Profile 1 uses an eight-byte unsigned big-endian frame length followed by strict
UTF-8 JSON. Empty and oversized frames, duplicate object keys, invalid Unicode,
nonfinite numbers and trailing data refuse. Fields are exact. Stdout contains
frames only; the worker emits no diagnostics or caller data.

| Frame | Exact fields |
|---|---|
| init | `kind:"init"`, `generation` (32-character string), `protocol:1`, `plain` (boolean), `key` (canonical Base64 or null) |
| ready | `kind:"ready"`, `generation`, `protocol:1`, `release`, `rules`, `source`, `corpus` |
| text request | `kind:"redact"`, `generation`, `id`, `mode:"text"`, `text` |
| value request | `kind:"redact"`, `generation`, `id`, `mode:"value"`, `value` |
| success | `kind:"result"`, `generation`, `id`, `result`, `hits` |
| core failure | `kind:"result"`, `generation`, `id`, `error:"core_failure"` |

The client generates the generation token and verifies every ready identity
field against its packaged manifest. Request IDs are consecutive decimal strings
starting at `"1"`. Results carry the same generation and ID. Hits are unique
rule/count objects with positive integer counts. Structured values preserve JSON
types and arbitrary-precision integers. Unsupported representations refuse.

Each caller owns its key. Initialization sends key bytes through private stdin,
never argv, environment, diagnostics or metadata. Keyed mode requires 16–65,536
bytes. Plain mode requires explicit client opt-in and a null wire key.

Requests are capped at 2 MiB of JSON payload, replies at 8 MiB. The client has a
default five-second encompassing deadline, configurable above zero and at most
60 seconds. The deadline includes validation, initialization, framing, I/O and
response checks. One client admits one call at a time; concurrency refuses
`busy`. Use separate clients for separate trust domains and reload keys by
creating a new client.

Malformed replies, wrong identity, worker death, core errors and timeouts raise
`CaviarError` with a stable code and no fallback content. A broken generation is
killed and reaped; a later call may create a fresh worker. Failed requests are
never automatically replayed. `close()` is terminal. A client inherited across
fork refuses. Every caller must abort persistence/export on failure.

For `value()`, the caller must keep the entire input tree unchanged until the
call returns. The client serializes its own calls but does not lock caller-owned
objects. Concurrent mutation can invalidate type validation, request-size and
memory bounds; callers must synchronize access or pass a stable private copy.

Domain validation bounds both JSON representation and aggregate expansion.
Removing it can invalidate request-size and memory bounds as well as value
validation; mutation probes must remain memory-capped and externally reaped.
