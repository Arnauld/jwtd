# JWTd


      curl  -d '{"aid":"AGENT:007", "huk":["r001", "r002"]}' \
            -H "Content-Type: application/json" \
            http://localhost:8080/sign?generate=iat,exp

If `jwt` cli is installed (https://github.com/mike-engel/jwt-cli)

      curl  -s -d '{"aid":"AGENT:007", "huk":["r001", "r002"]}' \
            -H "Content-Type: application/json" \
            http://localhost:8080/sign\?generate\=iat,exp,iss \
            | jq -r . | jwt decode -

## Building and Running a Cargo Project

      cargo build


## Building for Release

      cargo build --release


## Docker (or without rust env.) build

      docker build -t technbolts/jwtd .


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
