# syntax=docker/dockerfile:1
FROM rust:1.67 as builder
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
  rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
COPY . /home/rust/src
RUN cargo build --target x86_64-unknown-linux-musl --release

FROM alpine:3.13.5 as final
WORKDIR /app
EXPOSE 8000
ENV TZ=Etc/UTC \
    APP_USER=appuser
RUN addgroup -S $APP_USER \
    && adduser -S -g $APP_USER $APP_USER
RUN apk update \
    && apk add --no-cache ca-certificates tzdata \
    && rm -rf /var/cache/apk/*
COPY --from=builder /home/rust/src/target/x86_64-unknown-linux-musl/release/jwtd /app/jwtd
RUN chown -R $APP_USER:$APP_USER /app/jwtd
USER $APP_USER
CMD ["/app/jwtd"]