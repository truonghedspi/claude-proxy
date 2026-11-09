# Architecture

## Scope

Managed Proxy is an authenticated HTTP forward proxy for Claude Code and
other clients that support `HTTP_PROXY`/`HTTPS_PROXY`. It is deliberately a
TLS pass-through proxy: it authenticates the client before opening an upstream
connection, but it does not decrypt HTTPS or inspect model credentials inside
the tunnel.

```text
Claude Code
    │ HTTP_PROXY / HTTPS_PROXY
    │ Proxy-Authorization: Basic user:password
    ▼
Private listener / mTLS edge
    ▼
Rust Tokio data plane
    ├─ parse + size limits
    ├─ authenticate against in-memory policy
    ├─ domain allowlist check
    └─ async upstream TCP + CONNECT tunnel
    ▼
api.anthropic.com / approved domains

Operator ── CLI ──► SQLite control-plane database
                         │
                         └─ proxy refreshes policy every 2 seconds
```

## Components

### Data plane

`src/main.rs` accepts TCP connections with Tokio. Each connection is handled
by an async task; CONNECT traffic is relayed with
`tokio::io::copy_bidirectional`. Authentication uses Argon2 verification in
Tokio's blocking pool so expensive password work does not block the async
reactor. A semaphore caps concurrent verification (`AUTH_CONCURRENCY`, default
`4`) because each Argon2 operation has a non-trivial memory cost. The data
plane keeps users and domains in an immutable snapshot and does not query
SQLite for every packet.

The current limits are intentionally conservative:

- 64 KiB maximum request-header buffer.
- 10 seconds for initial upstream connect and request-header reads.
- 60 seconds idle timeout for a tunnel/response copy.
- Domain policy is checked before DNS connection establishment.
- No arbitrary `CONNECT host:port` without an allowlisted host.

### Control plane

The CLI manages a local SQLite database:

- `users`: normalized email, Argon2 password hash, active state.
- `domains`: normalized root domain; subdomains are included.

The service reloads policy every two seconds. SQLite is suitable for one node
or a small private deployment. It is not a shared multi-replica control plane.
For multiple replicas, replace it with a versioned policy service backed by
PostgreSQL/Redis and publish policy changes through a stream or watch API.

## Request flow

1. Client opens a TCP connection to the proxy.
2. Proxy parses only the request header and enforces the size/time limits.
3. `Proxy-Authorization` is validated against the current user snapshot.
4. The target hostname is normalized and matched against the domain allowlist.
5. Only after both checks pass does the proxy dial upstream.
6. For HTTPS, proxy returns `200 Connection Established` and copies bytes in
   both directions without TLS termination.
7. For plain HTTP, the absolute-form request target is rewritten to origin
   form, proxy credentials are stripped, and the request is sent upstream.

## Security model

The proxy credential authenticates a client to this proxy; it is not an
Anthropic credential. Keep the two secrets separate. Never put a real
Anthropic API key in the proxy username/password or in logs.

Recommended production boundary:

- Bind the proxy to a private interface or private load balancer.
- Terminate TLS/mTLS at an edge proxy such as Envoy, HAProxy or Nginx.
- Permit only the proxy port from trusted client networks.
- Store the SQLite file on encrypted persistent storage with mode `0600`.
- Use unique long random passwords per user and rotate them by replacing the
  user record.
- Log identity, target domain, result code and latency; never log auth headers,
  request bodies, prompts or upstream tokens.

## Scaling model

The data path is connection-oriented. Scale vertically first by increasing
file-descriptor limits and validating CPU/memory under concurrent CONNECT
load. Scale horizontally when one node's connection count or egress capacity
is the bottleneck.

For horizontal scaling:

1. Put a TCP load balancer in front of N identical proxy replicas.
2. Move policy to a shared store with an atomic policy version.
3. Cache the active policy in each replica and refresh by version/watch.
4. Use a shared identity/secret-management system; do not copy SQLite files
   between replicas.

The important performance invariant is that the hot tunnel path performs no
database or filesystem I/O. TLS is passed through, avoiding a second TLS
handshake and certificate management inside the service.

## Known boundaries

This service is not a TLS inspection gateway, DLP engine, or general-purpose
service mesh proxy. It does not provide an admin HTTP API, metrics endpoint,
automatic certificate issuance, or multi-node policy consensus yet. Those
capabilities belong at the deployment/control-plane layer described in the
deployment guide.
