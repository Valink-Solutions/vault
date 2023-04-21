FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef

WORKDIR /app

RUN apt update && apt install lld clang -y


FROM chef as planner

COPY . .

RUN cargo chef prepare --recipe-path rescipe.json

FROM chef AS builder

COPY --from=planner /app/rescipe.json rescipe.json

RUN cargo chef cook --release --recipe-path rescipe.json

COPY . .

ENV SQLX_OFFLINE true

RUN cargo build --release


FROM debian:bullseye-slim AS runtime

WORKDIR /app

RUN apt-get update -y \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/vault vault

# COPY configuration configuration

ENV APP_ENVIRONMENT production

ENTRYPOINT [ "./vault" ]