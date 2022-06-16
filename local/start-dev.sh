#!/bin/sh

JWT_PRIV_KEY_LOCATION=./key_prv.pem RUST_LOG="jwtd=info" RUST_BACKTRACE=1 PORT=8080 cargo run