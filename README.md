# JWTd

[![GitHub license](https://img.shields.io/github/license/Arnauld/jwtd.svg)](https://github.com/Arnauld/jwtd/blob/master/LICENSE)
[![GitHub release](https://img.shields.io/github/release/Arnauld/jwtd.svg)](https://GitHub.com/Arnauld/jwtd/releases/)
[![Docker](https://badgen.net/badge/icon/docker?icon=docker&label)](https://hub.docker.com/r/technbolts/jwtd/tags)
[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/Arnauld/jwtd/Rust)](https://github.com/Arnauld/jwtd/actions/workflows/rust.yml)

      curl  -d '{"aid":"AGENT:007", "huk":["r001", "r002"]}' \
            -H "Content-Type: application/json" \
            http://localhost:8080/sign?generate=iat,exp,iss


      curl -d '{"aid":"AGENT:007", "huk":["r001", "r002"], "iss":"tok"}' \
            -H "Content-Type: application/json" \
            -H "x-api-key: $API_KEY" \
            http://localhost:$PORT/sign?generate=iat,exp


      echo -n '{"hash":"$2b$07$WkBvSy5KcOQ4Wm1WhgVJveS4xYHOlGFP/c5kwb7Xz3H15/1lXFEZK", "plain":"CarmenMcCallum"}' > tmp/data.txt
      curl -X POST -d @tmp/data.txt \
            -H "Content-Type: application/json" \
            http://localhost:$PORT/bcrypt/check



If `jwt` cli is installed (https://github.com/mike-engel/jwt-cli)

      curl  -s -d '{"aid":"AGENT:007", "huk":["r001", "r002"]}' \
            -H "Content-Type: application/json" \
            http://localhost:8080/sign?generate=iat,exp,iss \
            | jwt decode -

Override default token duration (when generating `exp`)

      curl  -d '{"aid":"AGENT:007", "huk":["r001", "r002"]}' \
            -H "Content-Type: application/json" \
            http://localhost:8080/sign?generate=iat,exp,iss&duration_seconds=180

## Building and Running a Cargo Project

      cargo build

      cd local
      # start jwtd server
      ./start-dev.sh

      cd local
      # launch sample usecases
      ./usecases.sh

### Powershell

````powershell
$Env:JWT_PRIV_KEY_LOCATION="$pwd\local\key_prv.pem"
cargo run
````

## Release

      # 1. update Cargo.toml/package.version
      cargo install cargo-edit
      cargo set-version 0.5.10

      # 2. build app (this also update Cargo.lock)
      cargo build --release

      # 3. track all changes
      git add Cargo.toml Cargo.lock README.md
      git commit -m "release: v0.5.10"
      git tag v0.5.10
      
      # 4. push changes, this will trigger github action and release Docker image
      git push --tags


Troubleshoots when installing `cargo-edit`

      sudo apt update
      sudo apt install pkg-config libssl-dev


Debug release (dependency hell!!)

````bash
podman run \
-v $(pwd)/src:/home/rust/src/src \
-v $(pwd)/Cargo.toml:/home/rust/src/Cargo.toml \
-v $(pwd)/Cargo.lock:/home/rust/src/Cargo.lock \
-w /home/rust/src \
-it rust:1.67.0 /bin/bash
#-it ekidd/rust-musl-builder:1.57.0 /bin/bash
````


## Docker (or without rust env.) build

      podman build -t technbolts/jwtd:LOCAL .
      podman run -v $(pwd)/local:/keys -e JWT_PRIV_KEY_LOCATION=/keys/key_prv.pem  -it technbolts/jwtd:LOCAL

      docker tag -i 7358d9f4b652 technbolts/jwtd:0.1.0
      docker login -u xxxx -p xxxx
      docker push technbolts/jwtd:0.1.0

## Local setup (for testing purpose)

      openssl genrsa -out key_prv.pem 2048
      openssl rsa -in key_prv.pem -outform PEM -pubout -out key_pub.pem


# Troubleshoots

      error: linker `cc` not found
      |
      = note: No such file or directory (os error 2)

      sudo apt install build-essential

# Buffer

        #!/bin/bash
        function urldecode() { : "${*//+/ }"; echo -e "${_//%/\\x}"; }
        DATA_B64ENC=$(cat data.b64-urlencoded)
        DATA_B64DEC=$(urldecode $DATA_B64ENC)
        echo $DATA_B64DEC > data.b64
        cat data.b64 | base64 -d > data.raw
        openssl rsautl -inkey priv_key.pem -decrypt -oaep -in data.raw
