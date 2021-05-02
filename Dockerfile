# syntax=docker/dockerfile:1
FROM ekidd/rust-musl-builder:1.51.0 as builder
WORKDIR /home/rust/src
COPY . /home/rust/src
RUN cargo build --release


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
CMD ["./jwtd"]