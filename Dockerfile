# syntax=docker/dockerfile:1
FROM ekidd/rust-musl-builder:1.51.0 as builder
WORKDIR /home/rust/src
COPY . /home/rust/src
RUN cargo build --release


FROM alpine:3.13.5 as final
ARG UID=1001
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
USER appuser
WORKDIR /app
COPY --from=builder /home/rust/src/target/x86_64-unknown-linux-musl/release/jwtd /app/jwtd

EXPOSE 8000
CMD ["./jwtd"]
