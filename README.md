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
      cargo set-version 0.5.11

      # 2. build app (this also update Cargo.lock)
      cargo build --release

      # 3. track all changes
      git add Cargo.toml Cargo.lock README.md
      git commit -m "release: v0.5.11"
      git tag v0.5.11
      
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

# Environment Variables

This application supports several environment variables to control its behavior.

## Server configuration
- **`ADDR`**:
The bind address to listen for requests
- **`PORT`**:
The port to listen for requests
- **`RUST_LOG`**:
Controls the logging level for Rust applications, allowing you to specify which logs should be shown during the execution. By setting this variable, you can adjust the verbosity of the logs for debugging or monitoring purposes.

## Token configuration
- **`API_KEYS`**:
A list of API keys used to authenticate requests. This variable should contain a comma-separated list of keys.
- **`JWT_ISSUER`**:
iss claims value if required in 'generated' query param

## CORS Configuration (Cross-Origin Resource Sharing)
These environment variables allow you to manage security and access control mechanisms for your API.

- **`CORS_ENABLED`**:  
  A boolean flag to enable or disable CORS. Set this variable to `"true"` to allow cross-origin requests, or `"false"` to disable them. When disabled, no CORS-related headers are included in the server's responses.

- **`CORS_ALLOWED_ORIGINS`**:  
  Specifies the allowed origins for cross-origin requests. This should be a comma-separated list of origins (e.g., `"http://example.com,http://localhost:4200"`). The wildcard (`"*"`) can be used to allow requests from any origin, but it's recommended to be explicit for security reasons.

- **`CORS_ALLOWED_METHODS`**:  
  Defines the HTTP methods that are allowed when accessing resources. Common values include `"GET,POST,OPTIONS"`, but you can add others such as `"PUT,DELETE"` based on your API's needs. This restricts which methods clients can use.

- **`CORS_ALLOWED_HEADERS`**:  
  Specifies the allowed headers in requests. You can define which headers clients are allowed to send, such as `"Authorization,Content-Type"`. This is useful when allowing credentials or custom content types.

- **`CORS_ALLOW_CREDENTIALS`**:  
  A boolean flag (`"true"` or `"false"`) that indicates whether or not the response can be exposed when credentials (cookies or HTTP authentication) are included in cross-origin requests. Set this to `"true"` to allow credentials.

- **`CORS_MAX_AGE`**:  
  Defines the maximum time (in seconds) that the results of a preflight request can be cached. For example, `"86400"` (24 hours) will allow the browser to cache preflight responses for 24 hours, reducing the number of preflight requests. Default value is typically 86400 seconds (1 day).

- **`CORS_EXPOSE_HEADERS`**:  
  A comma-separated list of headers that the client is allowed to access in the response. By default, only a few headers like `Content-Type` are exposed. If your API sends custom headers that clients need to access, list them here (e.g., `"X-Custom-Header,X-Another-Header"`).

- **`CORS_ALLOW_PRIVATE_NETWORK`** (optional, not available in all versions):  
  A boolean flag (`"true"` or `"false"`) that indicates whether cross-origin requests from private networks are allowed. This is useful for allowing access from internal networks, but should be handled carefully for security reasons.

### Example Usage

To enable CORS with specific origins, methods, and headers:

```bash
CORS_ENABLED=true
CORS_ALLOWED_ORIGINS=http://example.com,http://localhost:4200
CORS_ALLOWED_METHODS=GET,POST,OPTIONS
CORS_ALLOWED_HEADERS=Authorization,Content-Type
CORS_ALLOW_CREDENTIALS=true
CORS_MAX_AGE=86400
CORS_EXPOSE_HEADERS=X-Custom-Header,X-Another-Header
