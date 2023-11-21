#!/bin/bash

API_KEY="invli"
PORT=8080
mkdir tmp/

echo "========================================================================="
echo "  HEALTH CHECK  "
echo "========================================================================="

HEALTH=`curl -s -H "Content-Type: application/json" http://localhost:$PORT/health`
echo "HEALTH...: ${HEALTH}"
echo ""

echo ""
echo "========================================================================="
echo "  SIGN CLAIMS  (no api key provided)"
echo "========================================================================="
TOKEN=`curl -s -d '{"aid":"AGENT:007", "huk":["r001", "r002"]}' \
            -H "Content-Type: application/json" \
            http://localhost:$PORT/sign?generate=iat,exp,iss`
echo "TOKEN....: ${TOKEN}"

echo ""
echo "========================================================================="
echo "  SIGN CLAIMS  "
echo "========================================================================="
TOKEN=`curl -s -d '{"aid":"AGENT:007", "huk":["r001", "r002"]}' \
            -H "Content-Type: application/json" \
            -H "x-api-key: $API_KEY" \
            http://localhost:$PORT/sign?generate=iat,exp,iss`
echo "TOKEN....: ${TOKEN}"

echo ""
echo "========================================================================="
echo "  VERIFYING TOKENs  "
echo "========================================================================="
VERIFY=`curl -s -d $TOKEN \
        -H "Content-Type: application/json" \
        -H "x-api-key: $API_KEY" \
        http://localhost:$PORT/verify`
echo "VERIFY (valid)...............: ${VERIFY}"

TOKEN=`curl -s -d '{"aid":"AGENT:007", "huk":["r001", "r002"], "iss":"tok"}' \
            -H "Content-Type: application/json" \
            -H "x-api-key: $API_KEY" \
            http://localhost:$PORT/sign?generate=iat,exp`
VERIFY=`curl -s -d $TOKEN \
        -H "Content-Type: application/json" \
        -H "x-api-key: $API_KEY" \
        http://localhost:$PORT/verify`
echo "VERIFY (invalid issuer)......: ${VERIFY}"

TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.hop.hip"
VERIFY=`curl -s -d $TOKEN \
        -H "Content-Type: application/json" \
        -H "x-api-key: $API_KEY" \
        http://localhost:$PORT/verify`
echo "VERIFY (bad format token)....: ${VERIFY}"


echo ""
echo "========================================================================="
echo "  ENCRYPT / DECRYPT "
echo "========================================================================="
echo -n "Carmen McCallum" > tmp/data.txt
ENCRYPTED=$(curl --silent -X POST -d @tmp/data.txt -H "Content-Type: text/plain" -H "x-api-key: $API_KEY" http://localhost:$PORT/encrypt)
echo "ENCRYPTED (b64)..: $ENCRYPTED"
echo -n "$ENCRYPTED" > tmp/encrypted.b64
cat tmp/encrypted.b64 | base64 --decode > tmp/encrypted.raw

# decrypt using openssl
echo "OPENSSL..........: '`openssl rsautl -inkey key_prv.pem -decrypt -oaep -in tmp/encrypted.raw`'"

DECRYPTED=$(curl --silent -X POST -d @tmp/encrypted.b64 -H "Content-Type: text/plain" -H "x-api-key: $API_KEY" http://localhost:$PORT/decrypt)
echo "DECRYPTED (b64)..: '$DECRYPTED'"
echo "DECRYPTED........: '`echo $DECRYPTED | base64 --decode`'"


echo ""
echo "========================================================================="
echo "  BCRYPT/CHECK "
echo "========================================================================="
echo -n '{"hash":"$2b$07$WkBvSy5KcOQ4Wm1WhgVJveS4xYHOlGFP/c5kwb7Xz3H15/1lXFEZK", "plain":"CarmenMcCallum"}' > tmp/data.txt
VERIFY=$(curl --silent -X POST -d @tmp/data.txt -H "Content-Type: application/json" http://localhost:$PORT/bcrypt/check)
echo "VERIFY..(OK)................: $VERIFY"

echo -n '{"hash":"$2b$07$WkBvSy5KcOQ4Wm1WhgVJveS4xYHOlGFP/c5kwb7Xz3H15/1lXFEZK", "plain":"Travis"}' > tmp/data.txt
VERIFY=$(curl --silent -X POST -d @tmp/data.txt -H "Content-Type: application/json" http://localhost:$PORT/bcrypt/check)
echo "VERIFY..(NOK)...............: $VERIFY"

echo -n '{"hash":"$2b$07$WkBvSy5KcOQ4Wm1WhgVJveS4xYHOlGF", "plain":"Travis"}' > tmp/data.txt
VERIFY=$(curl --silent -X POST -d @tmp/data.txt -H "Content-Type: application/json" http://localhost:$PORT/bcrypt/check)
echo "VERIFY..(bcrypt invalid 1)..: $VERIFY"

echo -n '{"hash":"hey!", "plain":"Travis"}' > tmp/data.txt
VERIFY=$(curl --silent -X POST -d @tmp/data.txt -H "Content-Type: application/json" http://localhost:$PORT/bcrypt/check)
echo "VERIFY..(bcrypt invalid 2)..: $VERIFY"
