# Production deployment

## Release checklist

Before exposing the service to users:

- Build and test the exact release artifact: `cargo test` and
  `cargo build --release`.
- Add only the domains required by the Claude Code version and organization.
- Create a unique proxy user per human or workload.
- Store the database on encrypted persistent storage and back it up.
- Bind the proxy to a private address; do not expose port 8080 directly to the
  internet.
- Put an mTLS-capable edge proxy in front of it if clients are not on a fully
  trusted private network.
- Set file-descriptor, process, memory and egress limits.
- Set `AUTH_CONCURRENCY` from measured memory headroom and keep
  `AUTH_CACHE_TTL_SECS` short enough for the organization's revocation policy.
- Set `RUST_LOG=managed_proxy=info` (or `debug` during an incident) and
  `LOG_FORMAT=json` when shipping logs to a collector. Configure rotation and
  retention outside the binary.
- Test the failure cases: wrong credentials, disallowed domain, upstream DNS
  failure, upstream timeout, and process restart.

## Docker

Build from the repository root:

```bash
docker build -f deploy/Dockerfile -t managed-proxy:0.1.0 .
```

Create the policy database on a persistent host volume, then run the control
plane commands in a short-lived container:

```bash
docker volume create managed-proxy-data
docker run --rm -v managed-proxy-data:/var/lib/managed-proxy \
  managed-proxy:0.1.0 --db /var/lib/managed-proxy/proxy.db \
  add-user truong.hn.1994@gmail.com --password 'GENERATE-A-LONG-RANDOM-SECRET'

docker run --rm -v managed-proxy-data:/var/lib/managed-proxy \
  managed-proxy:0.1.0 --db /var/lib/managed-proxy/proxy.db \
  add-domain api.anthropic.com

docker run --rm --name managed-proxy \
  -p 127.0.0.1:8080:8080 \
  -v managed-proxy-data:/var/lib/managed-proxy \
  managed-proxy:0.1.0 --db /var/lib/managed-proxy/proxy.db \
  serve --listen 0.0.0.0:8080
```

For real deployments, place a private load balancer or mTLS edge in front of
the container and do not publish the container port publicly.

## systemd

Install the release binary at `/opt/managed-proxy/managed-proxy`, create the
database directory, and install the unit:

```bash
sudo install -d -o managed-proxy -g managed-proxy -m 0700 /var/lib/managed-proxy
sudo install -o root -g root -m 0755 target/release/managed-proxy /opt/managed-proxy/managed-proxy
sudo install -m 0644 deploy/systemd/managed-proxy.service /etc/systemd/system/managed-proxy.service
sudo systemctl daemon-reload
sudo systemctl enable --now managed-proxy
sudo journalctl -u managed-proxy -f
```

The unit intentionally listens on `127.0.0.1:8080`. Change that only when a
firewall/private load balancer protects the interface.

## TLS and mTLS edge

The Rust service does not terminate TLS. Use an edge proxy for:

- server certificate and TLS policy;
- client certificate verification (mTLS) if required;
- source-network ACLs and connection limits;
- access logs with secrets removed.

The edge must preserve HTTP proxy `CONNECT` semantics and forward the
`Proxy-Authorization` header to the Rust service, or perform identity mapping
to a service-specific proxy credential. Do not terminate and re-encrypt
upstream Claude HTTPS unless the organization explicitly accepts TLS
inspection and manages client trust roots.

## Operations

### Backups and rollback

Stop writes or use SQLite's online backup mechanism before copying `proxy.db`.
Keep encrypted, timestamped backups and test restore periodically. Rollback is:

1. stop the service;
2. restore the last known-good database and binary;
3. start the service;
4. run the wrong-user, blocked-domain and allowed-domain smoke tests.

### Monitoring

Until a native metrics endpoint is added, monitor:

- process liveness and restart count;
- listening socket and established connection count;
- CPU, RSS, file descriptors and egress bandwidth;
- journal lines containing connection failures;
- upstream DNS/connect timeout rates;
- `407` and `403` counts at the edge or log collector.

Alert on repeated upstream failures, unexpected growth in active connections,
disk exhaustion, and any policy database permission change.

### Incident response

For a suspected credential leak, immediately remove or disable the user,
rotate the upstream/provider credential separately, and preserve only
metadata logs needed for investigation. Do not dump proxy headers or request
bodies into incident logs.

## Production gaps to close before internet exposure

The current binary is appropriate for a private, controlled deployment. For
internet-facing or multi-tenant use, add a versioned policy API, centralized
secret management, structured audit events, Prometheus metrics, admin RBAC,
per-user rate limits, circuit breakers, and a fuzz/integration test suite for
HTTP parsing and CONNECT handling.
