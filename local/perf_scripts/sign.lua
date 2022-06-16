-- example HTTP POST script which demonstrates setting the
-- HTTP method, body, and adding a header

wrk.method = "POST"
wrk.body   = '{"aid":"AGENT:007", "huk":["r001", "r002"]}'
wrk.headers["Content-Type"] = "application/json"