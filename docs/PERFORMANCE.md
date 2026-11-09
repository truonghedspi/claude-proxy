# Performance test report

## What was measured

`scripts/bench_e2e.py` starts a local echo upstream and drives the Rust proxy
with authenticated HTTPS `CONNECT` tunnels. It does not call Claude or any
provider, so the result measures the proxy data plane without consuming quota.
Each connection authenticates with one of N users, establishes a tunnel, and
exchanges a fixed payload repeatedly. The harness reports success/failure,
latency percentiles, throughput, and sampled proxy RSS/CPU/file descriptors.

Run it from the repository root after building:

```bash
cargo build --release
python3 scripts/bench_e2e.py --connections 100 --users 10 --repeats 10 --payload-kb 64
python3 scripts/bench_e2e.py --connections 500 --users 50 --repeats 5 --payload-kb 16
```

## Results on the current development machine

| Scenario | Success | p50 | p95 | p99 | Throughput | RSS peak | CPU peak | FD peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 connections / 10 users | 100/100 | 244 ms | 443 ms | 459 ms | 128.85 MiB/s | 83.25 MiB | 213.7% | 66 |
| 500 connections / 50 users | 500/500 | 1118 ms | 2084 ms | 2203 ms | 17.41 MiB/s | 95.62 MiB | 405.2% | 470 |
| 100 connections / 10 users, 10-connection waves with auth cache | 100/100 | 8.70 ms | 46.31 ms | 58.72 ms | 367.80 MiB/s | 4.00 MiB | 0.9% | 14 |

These are local-machine observations, not capacity guarantees. The test
includes Argon2 authentication on every new connection, which intentionally
stresses connection churn. Network distance, CPU model, kernel limits,
payload size, upstream behavior and the number of active long-lived tunnels
will change the result substantially.

## Finding and mitigation

The first 100-connection run, before the guard was added, reached roughly
733 MB RSS because all new connections could run Argon2 verification at once.
The proxy now uses `AUTH_CONCURRENCY=4` by default. This bounds expensive
password verification and kept the equivalent run below 84 MB RSS while all
100 connections still succeeded.

This is a deliberate trade-off: a burst beyond the semaphore queues at the
authentication boundary, increasing p95/p99 connection latency instead of
allowing unbounded memory growth. Tune it only after measuring the host's
memory headroom and acceptable login latency:

```bash
AUTH_CONCURRENCY=8 ./target/release/managed-proxy --db proxy.db serve --listen 127.0.0.1:8080
```

Successful credentials are also cached by a SHA-256 fingerprint for a short
TTL. Configure it with `AUTH_CACHE_TTL_SECS` (default `30`). The cache avoids
re-running Argon2 for the same proxy credential during connection reuse/churn,
while the short TTL limits the revocation delay. The benchmark's wave mode
demonstrated the expected effect: after the first wave, subsequent connections
used the cache and p50 fell below 10 ms on the test machine.

## File-descriptor interpretation

For a CONNECT tunnel, one client socket and one upstream socket are open, plus
listener/database/process descriptors. A rough planning estimate is therefore
`2 * active_tunnels + safety_margin` descriptors per replica. The benchmark's
500-connection run observed 470 descriptors because sampling did not always
land at the exact concurrency peak.

Production capacity testing must verify all layers together:

1. process `RLIMIT_NOFILE` and service-manager `LimitNOFILE`;
2. kernel TCP memory/backlog and ephemeral-port limits;
3. load-balancer connection limits and idle timeouts;
4. proxy active connections, RSS, CPU and FD count;
5. upstream connect latency, errors and bandwidth.

## Not yet a production capacity claim

The harness currently measures a single replica on one host and does not yet
include Prometheus metrics, long-running soak tests, packet loss, DNS failure,
upstream timeout, or multi-replica load balancing. Those are required before
setting an SLO or publishing a maximum supported connection count.
