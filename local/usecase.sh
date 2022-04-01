#!/bin/sh

PORT=8080

HEALTH=`curl -s -H "Content-Type: application/json" http://localhost:$PORT/health`
echo "HEALTH...: ${HEALTH}"

echo "========================================================================="
TOKEN=`curl -s -d '{"aid":"AGENT:007", "huk":["r001", "r002"]}' \
            -H "Content-Type: application/json" \
            http://localhost:$PORT/sign?generate=iat,exp,iss`
echo "TOKEN....: ${TOKEN}"

VERIFY=`curl -s -d $TOKEN -H "Content-Type: application/json" http://localhost:$PORT/verify`
echo "VERIFY...: ${VERIFY}"

echo "========================================================================="
TOKEN=`curl -s -d '{"aid":"AGENT:007", "huk":["r001", "r002"], "iss":"tok"}' \
            -H "Content-Type: application/json" \
            http://localhost:$PORT/sign?generate=iat,exp`
echo "TOKEN....: ${TOKEN}"

VERIFY=`curl -s -d $TOKEN -H "Content-Type: application/json" http://localhost:$PORT/verify`
echo "VERIFY...: ${VERIFY}"

echo "========================================================================="
TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.hop.hip"
echo "TOKEN....: ${TOKEN}"

VERIFY=`curl -s -d $TOKEN -H "Content-Type: application/json" http://localhost:$PORT/verify`
echo "VERIFY...: ${VERIFY}"
