# Argument pour spécifier le target
ARG TARGET_TRIPLE=x86_64-unknown-linux-musl

# syntax=docker/dockerfile:1
FROM rust:1.67.1 AS builder

ARG TARGET_TRIPLE
ENV TARGET_TRIPLE=${TARGET_TRIPLE}

WORKDIR /home/rust/src
RUN apt-get update && apt-get install -y \
  musl-dev \
  musl-tools \
  file \
  git \
  openssh-client \
  make \
  cmake \
  g++ \
  curl \
  pkgconf \
  ca-certificates \
  xutils-dev \
  libssl-dev \
  libpq-dev \
  automake \
  autoconf \
  libtool \
  protobuf-compiler \
  libprotobuf-dev \
  --no-install-recommends && \
  rm -rf /var/lib/apt/lists/* \
RUN rustup target add ${TARGET_TRIPLE}
RUN rustup component add rust-std --target ${TARGET_TRIPLE}

COPY . /home/rust/src

# When target is "aarch64-unknown-linux-musl", defining CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER and CC is required
RUN if [ "${TARGET_TRIPLE}" = "aarch64-unknown-linux-musl" ]; then \
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-gnu-gcc && \
        export CC=aarch64-linux-gnu-gcc; \
    fi && \
    cargo build --target ${TARGET_TRIPLE} --release
RUN ls -al ./target/

FROM alpine:3.13.5 AS final

ARG UID=1001
ARG TARGET_TRIPLE

ENV TARGET_TRIPLE=${TARGET_TRIPLE}
ENV TZ=Etc/UTC

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    appuser
RUN apk update \
    && apk add --no-cache ca-certificates tzdata \
    && rm -rf /var/cache/apk/*
USER ${UID}
WORKDIR /app
COPY --from=builder /home/rust/src/target/${TARGET_TRIPLE}/release/jwtd /app/jwtd

EXPOSE 8000
CMD ["./jwtd"]
