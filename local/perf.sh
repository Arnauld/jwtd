#!/bin/sh


wrk -t12 -c400 -d30s -s perf/sign.lua http://127.0.0.1:8080/sign
