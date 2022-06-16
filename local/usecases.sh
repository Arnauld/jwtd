#!/bin/bash

PORT=8080
mkdir tmp/

echo "========================================================================="
echo "  HEALTH CHECK  "
echo "========================================================================="

HEALTH=`curl -s -H "Content-Type: application/json" http://localhost:$PORT/health`
echo "HEALTH...: ${HEALTH}"
echo ""

echo "========================================================================="
echo "  SIGN CLAIMS  "
echo "========================================================================="
TOKEN=`curl -s -d '{"aid":"AGENT:007", "huk":["r001", "r002"]}' \
            -H "Content-Type: application/json" \
            http://localhost:$PORT/sign?generate=iat,exp,iss`
echo "TOKEN....: ${TOKEN}"

echo "========================================================================="
echo "  VERIFYING TOKENs  "
echo "========================================================================="
VERIFY=`curl -s -d $TOKEN -H "Content-Type: application/json" http://localhost:$PORT/verify`
echo "VERIFY (valid)...............: ${VERIFY}"

TOKEN=`curl -s -d '{"aid":"AGENT:007", "huk":["r001", "r002"], "iss":"tok"}' \
            -H "Content-Type: application/json" \
            http://localhost:$PORT/sign?generate=iat,exp`
VERIFY=`curl -s -d $TOKEN -H "Content-Type: application/json" http://localhost:$PORT/verify`
echo "VERIFY (invalid issuer)......: ${VERIFY}"

TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.hop.hip"
VERIFY=`curl -s -d $TOKEN -H "Content-Type: application/json" http://localhost:$PORT/verify`
echo "VERIFY (bad format token)....: ${VERIFY}"


echo "========================================================================="
echo "  ENCRYPT / DECRYPT "
echo "========================================================================="
echo -n "Carmen McCallum" > tmp/data.txt
ENCRYPTED=$(curl --silent -X POST -d @tmp/data.txt -H "Content-Type: text/plain" http://localhost:$PORT/encrypt)
echo "ENCRYPTED (b64)..: $ENCRYPTED"
echo -n $ENCRYPTED > tmp/encrypted.b64
echo $ENCRYPTED | base64 --decode > tmp/encrypted.raw

# decrypt using openssl
echo "OPENSSL..........: '`openssl rsautl -inkey key_prv.pem -decrypt -oaep -in tmp/encrypted.raw`'"

DECRYPTED=$(curl --silent -X POST -d @tmp/encrypted.b64 -H "Content-Type: text/plain" http://localhost:$PORT/decrypt)
echo "DECRYPTED (b64)..: '$DECRYPTED'"
echo "DECRYPTED........: '`echo $DECRYPTED | base64 --decode`'"
