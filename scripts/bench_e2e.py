#!/usr/bin/env python3
"""Local load test for the managed-proxy CONNECT data plane.

It uses a local echo upstream, so it measures proxy/network behavior without
calling an LLM or consuming provider quota.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import os
import statistics
import subprocess
import tempfile
import time
from pathlib import Path


def run_admin(binary: str, db: str, *args: str) -> None:
    subprocess.run([binary, "--db", db, *args], check=True, stdout=subprocess.DEVNULL)


def ps_sample(pid: int) -> tuple[float, float, int | None]:
    try:
        raw = subprocess.check_output(["ps", "-o", "rss=,pcpu=", "-p", str(pid)], text=True).strip()
        rss_kb, cpu = raw.split()
        fd_count = None
        try:
            fd_count = sum(1 for line in subprocess.check_output(["lsof", "-p", str(pid)], text=True, stderr=subprocess.DEVNULL).splitlines() if line)
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        return float(rss_kb) / 1024.0, float(cpu), fd_count
    except (subprocess.CalledProcessError, ValueError):
        return 0.0, 0.0, None


async def echo_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(1024 * 1024):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def one_client(proxy_port: int, upstream_port: int, email: str, password: str, payload: bytes, repeats: int) -> tuple[float, int]:
    started = time.perf_counter()
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    token = base64.b64encode(f"{email}:{password}".encode()).decode()
    writer.write((f"CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nProxy-Authorization: Basic {token}\r\n\r\n").encode())
    await writer.drain()
    response = await reader.readuntil(b"\r\n\r\n")
    if not response.startswith(b"HTTP/1.1 200"):
        raise RuntimeError(response.decode(errors="replace").split("\r\n", 1)[0])
    total = 0
    for _ in range(repeats):
        writer.write(payload)
        await writer.drain()
        remaining = len(payload)
        while remaining:
            chunk = await reader.read(min(remaining, 1024 * 1024))
            if not chunk:
                raise RuntimeError("upstream closed tunnel")
            remaining -= len(chunk)
        total += len(payload)
    writer.close()
    await writer.wait_closed()
    return time.perf_counter() - started, total


async def sample_resources(pid: int, stop: asyncio.Event, samples: list[tuple[float, float, int | None]]) -> None:
    while not stop.is_set():
        samples.append(ps_sample(pid))
        await asyncio.sleep(0.25)


async def wait_for_proxy(port: int) -> None:
    for _ in range(100):
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError("proxy did not start")


async def main(args: argparse.Namespace) -> None:
    root = Path(__file__).resolve().parents[1]
    binary = str(root / "target/release/managed-proxy")
    if not Path(binary).exists():
        raise SystemExit(f"missing release binary: {binary}")
    with tempfile.TemporaryDirectory(prefix="managed-proxy-bench-") as temp:
        db = str(Path(temp) / "bench.db")
        for index in range(args.users):
            run_admin(binary, db, "add-user", f"bench-{index}@example.test", "--password", args.password)
        run_admin(binary, db, "add-domain", "127.0.0.1")
        proxy = subprocess.Popen([binary, "--db", db, "serve", "--listen", f"127.0.0.1:{args.proxy_port}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        upstream = await asyncio.start_server(echo_handler, "127.0.0.1", args.upstream_port)
        try:
            await wait_for_proxy(args.proxy_port)
            resources: list[tuple[float, float, int | None]] = []
            stop = asyncio.Event()
            sampler = asyncio.create_task(sample_resources(proxy.pid, stop, resources))
            payload = os.urandom(args.payload_kb * 1024)
            started = time.perf_counter()
            batch_size = args.batch_size or args.connections
            results = []
            for start in range(0, args.connections, batch_size):
                tasks = [one_client(args.proxy_port, args.upstream_port, f"bench-{i % args.users}@example.test", args.password, payload, args.repeats) for i in range(start, min(start + batch_size, args.connections))]
                results.extend(await asyncio.gather(*tasks, return_exceptions=True))
            elapsed = time.perf_counter() - started
            stop.set()
            await sampler
            successes = [r for r in results if not isinstance(r, Exception)]
            failures = [str(r) for r in results if isinstance(r, Exception)]
            latencies = sorted(r[0] for r in successes)
            bytes_sent = sum(r[1] for r in successes)
            def percentile(p: float) -> float:
                if not latencies:
                    return 0.0
                return latencies[min(len(latencies) - 1, int(len(latencies) * p))] * 1000
            print(f"connections={args.connections} users={args.users} repeats={args.repeats} payload_kb={args.payload_kb}")
            print(f"success={len(successes)} failure={len(failures)} elapsed_s={elapsed:.3f}")
            print(f"latency_ms p50={percentile(.50):.2f} p95={percentile(.95):.2f} p99={percentile(.99):.2f}")
            print(f"throughput_mib_s={bytes_sent / max(elapsed, 0.001) / 1024 / 1024:.2f}")
            if resources:
                rss = [x[0] for x in resources]
                cpu = [x[1] for x in resources]
                fds = [x[2] for x in resources if x[2] is not None]
                print(f"proxy_rss_mb max={max(rss):.2f} avg={statistics.mean(rss):.2f}")
                print(f"proxy_cpu_percent max={max(cpu):.1f}")
                if fds:
                    print(f"proxy_fd_count max={max(fds)}")
            if failures:
                print(f"first_failure={failures[0]}")
            if len(successes) != args.connections:
                raise SystemExit(1)
        finally:
            upstream.close()
            await upstream.wait_closed()
            proxy.terminate()
            proxy.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--connections", type=int, default=100)
    parser.add_argument("--users", type=int, default=10)
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--payload-kb", type=int, default=64)
    parser.add_argument("--batch-size", type=int, default=0, help="run connections in waves; useful for measuring auth-cache reuse")
    parser.add_argument("--proxy-port", type=int, default=18180)
    parser.add_argument("--upstream-port", type=int, default=19190)
    parser.add_argument("--password", default="bench-password")
    asyncio.run(main(parser.parse_args()))
