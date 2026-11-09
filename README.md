# Managed Proxy

Rust/Tokio authenticated HTTP/HTTPS forward proxy. It is designed as a small
data-plane service: one async task per connection, no thread per socket, no
database read per packet, and HTTPS is passed through with `CONNECT` rather
than decrypted.

## Build

```bash
cargo build --release
```

## Administration

Passwords are stored as Argon2id-compatible password hashes. The database is
only used by the control plane; the running proxy reloads users and domains
every two seconds.

```bash
./target/release/managed-proxy --db proxy.db add-user truong.hn.1994@gmail.com --password 'change-me'
./target/release/managed-proxy --db proxy.db add-domain api.anthropic.com
./target/release/managed-proxy --db proxy.db add-domain statsig.anthropic.com
./target/release/managed-proxy --db proxy.db list-users
./target/release/managed-proxy --db proxy.db list-domains
./target/release/managed-proxy --db proxy.db remove-domain statsig.anthropic.com
./target/release/managed-proxy --db proxy.db remove-user truong.hn.1994@gmail.com
```

Adding `anthropic.com` also permits its subdomains. The proxy starts fail
closed: with no domain entries, no upstream destination is allowed.

## Run with Claude Code

```bash
./target/release/managed-proxy --db proxy.db serve --listen 127.0.0.1:8080

HTTPS_PROXY='http://truong.hn.1994%40gmail.com:change-me@127.0.0.1:8080' \
HTTP_PROXY='http://truong.hn.1994%40gmail.com:change-me@127.0.0.1:8080' \
claude
```

The proxy authenticates the `Proxy-Authorization` header before dialing an
upstream. Wrong users/passwords receive `407`; domains outside the allowlist
receive `403`.

## Operations dashboard

Run the admin dashboard on a separate private listener. The token is required
for the dashboard, JSON API and Prometheus endpoint; `/healthz` is intentionally
unauthenticated for a local health check.

```bash
ADMIN_TOKEN='replace-with-a-long-random-token' \
./target/release/managed-proxy --db proxy.db serve \
  --listen 127.0.0.1:8080 \
  --admin-listen 127.0.0.1:9090
```

Open `http://127.0.0.1:9090/` with an `Authorization: Bearer ...` header, or
query the endpoints directly:

```bash
curl http://127.0.0.1:9090/healthz
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:9090/api/metrics
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:9090/metrics
```

## Tracing and logging

Logs are structured with request IDs and include connection lifecycle, auth
result, cache hit, domain decision, upstream failure, bytes and duration. They
never include passwords, proxy authorization headers, prompts or request
bodies.

```bash
RUST_LOG=managed_proxy=info ./target/release/managed-proxy --db proxy.db serve --listen 127.0.0.1:8080
LOG_FORMAT=json RUST_LOG=managed_proxy=debug ./target/release/managed-proxy --db proxy.db serve --listen 127.0.0.1:8080
```

Use the default text format for local development and JSON for journald,
Docker log drivers or a central collector. In production, configure log
rotation/retention at the service manager or container platform.

## Performance and production boundary

- Tokio async I/O and `copy_bidirectional` are used for CONNECT tunnels.
- TCP_NODELAY is enabled; headers are capped at 64 KiB and idle tunnels at 60s.
- Argon2 verification is moved to Tokio's blocking pool so it cannot block the
  async reactor. `AUTH_CONCURRENCY` (default `4`) caps concurrent Argon2 work
  to protect memory during connection churn.
- Successful proxy credentials are cached by SHA-256 fingerprint for
  `AUTH_CACHE_TTL_SECS` (default `30`) so persistent/reused client credentials
  do not pay Argon2 on every new connection. Keep the TTL short for revocation.
- For multiple replicas, use an external policy store/cache and a control-plane
  API rather than sharing a local SQLite file. Put TLS/mTLS in front of the
  service, bind it to a private network, and add metrics, health checks, and
  connection/file-descriptor limits before public deployment.
- This is not a TLS MITM and cannot inspect credentials inside HTTPS. It only
  authenticates the client to the proxy.

## Production documentation

- [Architecture](docs/ARCHITECTURE.md): data plane, control plane, security
  boundaries, request flow and scaling model.
- [Deployment](docs/DEPLOYMENT.md): Docker and systemd deployment, TLS/mTLS
  edge termination, backups, rollout, monitoring and incident response.
- [Performance](docs/PERFORMANCE.md): repeatable local load test, measured
  results, file-descriptor planning and Argon2 memory protection.
- [SSO](docs/SSO.md): generic OIDC seam, Entra configuration, allow decision
  and mock/real E2E strategy.
