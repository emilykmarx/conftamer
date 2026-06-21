# Dynamically Tracking Contexts

## Instructions

**Terminal 1**: start target under delve (headless). Note: disable inlining for the HTTP library to ensure all breakpoints are hit. Use `dlv debug` to run a binary and `dlv test` to run tests.

```
# Run a binary
$ dlv debug --headless --listen=:2345 --api-version=2  --build-flags="-gcflags=net/http=-l" [directory] [args]
# Run tests
$ dlv test --headless --listen=:2345 --api-version=2  --build-flags="-gcflags=net/http=-l" [directory] [args]
```

**Terminal 2**: Run Delve client.

```
$ python3 delve_client/delve_client.py --output events.jsonl
```

This outputs raw results to `events.jsonl`. Each individual event will look something like this:

```
{"kind": "Request received", "goroutine_id": 110, "thread_id": 1767925, "file": "/home/tcr6/.go/src/net/http/server.go", "line": 2814, "message": {"r.Method": "GET", "r.URL.Path": "/config/", "r.URL.RawQuery": "(string)", "r.Header": "{:User-Agent :Accept-Encoding}", "r.RemoteAddr": "127.0.0.1:54128", "r.Proto": "HTTP/1.1"}, "context": {"source": "r.ctx", "type": "context.Context", "root_addr": "0x3be925e340c0", "frames_searched": [{"index": 0, "func": "net/http.(*ServeMux).ServeHTTP", "file": "/home/tcr6/.go/src/net/http/server.go", "line": 2814}]}}
```

**After running**, parse results using `group_by_context.py`. This will print a summary of all messages (sent and received) that share the same context (i.e., potential edges in our graph), including how many times this relationship was observed.
For example:

```
({"kind": "req recvd", "verb": "GET", "endpoint": "/version"}, {"kind": "resp sent", "verb": "GET", "endpoint": "/version", "code": "200"})  # 2x
```

## Use-Cases

### Context blog example

Simple example from original [blog post](https://go.dev/blog/context) on contexts. [Repo here](https://github.com/thearossman/contextblog).

Run as a binary:

```
dlv debug --headless --listen=:2345 --api-version=2 .
```

This is a good sanity check.

### Caddy:

**Major Gotcha with Caddy**: A stale Caddy server from a previous test can still be running, which won't be caught in the current Delve run. Find the process and kill it, e.g.:

```
$ ss -tlnp | grep 2999; lsof -i :2999 2>/dev/null | head -10
LISTEN 0      4096       127.0.0.1:2999       0.0.0.0:*    users:(("caddy-test",pid=1623641,fd=12))
COMMAND       PID USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
caddy-tes 1623641 tcr6   12u  IPv4 12601032      0t0  TCP localhost:2999 (LISTEN)
$ kill 1623641
$ curl -s http://localhost:2999/config/ # validate that this returns nothing
```

[Repo](https://github.com/caddyserver/caddy) here. It has a few unit tests and a much more extensive suite of integration tests.

Unit tests:

```
dlv test --headless --listen=:2345 --api-version=2 ./modules/caddyhttp/reverseproxy/ -- -test.short -test.v
```

Integration tests (note: disable timeout):

```
dlv test --headless --listen=:2345 --api-version=2 --build-flags="-gcflags=net/http=-l" ./caddytest/integration/ -- -test.v -test.timeout 0
```

## TODOS

- Some measure of coverage?
- Should we filter out double sent / double received relationships?
- Print out statistics:
    * Message patterns: (e.g., "request received --> response sent was X\% of graph edges")
    * Assumptions we leverage (e.g., "in X\% of cases, the context was embedded in the message struct")