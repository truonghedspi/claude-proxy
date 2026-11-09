FROM rust:1.85-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home --home-dir /nonexistent --shell /usr/sbin/nologin managed-proxy \
    && install -d -o managed-proxy -g managed-proxy -m 0700 /var/lib/managed-proxy
COPY --from=build /src/target/release/managed-proxy /usr/local/bin/managed-proxy
USER managed-proxy
WORKDIR /var/lib/managed-proxy
ENTRYPOINT ["/usr/local/bin/managed-proxy"]
