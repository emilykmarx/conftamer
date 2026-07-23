# In-library context tracking (Delve-free)

Instead of setting breakpoints in Delve (see [`README.md`](README.md)), the
context and message tracing logic is compiled directly into a cloned copy of the
Go standard library. Any program built with the toolchain produces a `jsonl` file
that can be used with the scripts in `analysis/`.

## How to Use

### Modify Go

Apply [`go-inlibrary.patch`](go-inlibrary.patch) to a cloned copy of Go.
I directly copied the contents of `/usr/local/go` into `~/go-conftamer/`
and applied the patch there.

### Set Required Environment Variables

- **`GOTOOLCHAIN=local`** — Without it, Go's `auto` toolchain may download
  a new fork of Go (e.g., 1.25.x to satisfy Prometheus `go 1.25.0` directive).
- **`CONFTAMER_EVENTS=/path/to/output.jsonl`** — where events are written.

Optional:

- **`CONFTAMER_JOIN=addr`** — use the legacy heap-address join key instead of the
  default explicit request-ID (`id:N`). May be useful to compare the two approaches.

### Output

**Append semantics:** the file is opened `O_APPEND`.
Delete (or point `CONFTAMER_EVENTS` at a fresh path) between runs you want to
analyze in isolation:

```
rm -f /home/tcr6/conftamer/contexttrack/events/prom.jsonl
```

Each line looks like:

```json
{"kind":"Request sent","goroutine_id":435,"file":".../net/http/transport.go","line":599,
 "message":{"req.Method":"GET","req.URL.Host":"127.0.0.1:9090","req.URL.Path":"/metrics","req.URL.RawQuery":""},
 "context":{"source":"req.Context()","type":"context.Context","root_addr":"id:7"},
 "request_id":{"method":"GET","host":"127.0.0.1:9090","path":"/metrics"},"api_id":"github.com/prometheus"}
```

Use `analysis/group_by_context.py` to see context groups and `analysis/message_graph.py`
to generate the full, directed grah.

## Running Prometheus tests

All tests:

```bash
cd ~/prometheus-src
EV=~/conftamer/contexttrack/events/prom_test.jsonl
rm -f "$EV"

GOTOOLCHAIN=local CONFTAMER_EVENTS="$EV" \
  ~/go-conftamer/bin/go test -count=1 ./...
```

Or, just one test, e.g.:

```bash
GOTOOLCHAIN=local CONFTAMER_EVENTS="$EV" \
  ~/go-conftamer/bin/go test ./scrape/ -run TestTargetScraperScrapeOK -count=1
```

Note: use `-count=1` to ensure that packages with cached results get re-executed.

`./scrape/` (scrape client + response handling) and `./web/` (API server) are the
most productive packages to point this at.

## Running Caddy tests

All integration tests:

```bash
cd ~/caddy
EV=~/conftamer/contexttrack/events/caddy_test.jsonl
rm -f "$EV"

GOTOOLCHAIN=local CONFTAMER_EVENTS="$EV" \
  ~/go-conftamer/bin/go test -count=1 -p 1 ./caddytest/integration/
```

Note: use `-p 1` to disable parallelization.
Each integration test starts a Caddy server on the same port, so we can't
actually execute parallel test processes.

Or, just one test, e.g.:

```bash
GOTOOLCHAIN=local CONFTAMER_EVENTS="$EV" \
  ~/go-conftamer/bin/go test -count=1 -p 1 ./caddytest/integration/ \
  -run TestReverseProxySubroutes
```

Unit tests:

```bash
GOTOOLCHAIN=local CONFTAMER_EVENTS="$EV" \
  ~/go-conftamer/bin/go test -count=1 ./modules/caddyhttp/reverseproxy/
```

## Running Kubernetes tests

Note: `etcd` must be on `PATH` — the integration test framework calls
`exec.LookPath("etcd")` and fails hard otherwise. If missing:

```bash
cd ~/kubernetes && hack/install-etcd.sh
export PATH="$PATH:$HOME/kubernetes/third_party/etcd"
```

All tests in the endpoints integration package:

```bash
cd ~/kubernetes
EV=~/conftamer/contexttrack/events/k8s_test.jsonl
rm -f "$EV"

GOTOOLCHAIN=local CONFTAMER_EVENTS="$EV" \
  ~/go-conftamer/bin/go test -count=1 ./test/integration/endpoints/
```

Or, just one test, e.g.:

```bash
GOTOOLCHAIN=local CONFTAMER_EVENTS="$EV" \
  ~/go-conftamer/bin/go test -count=1 ./test/integration/endpoints/ \
  -run TestEndpointWithMultiplePods
```

`./test/integration/endpoints` (apiserver + etcd) is the primary package.

TODO: other packages under `./test/integration/` might have other prereqs.

## Analyzing the output

Same scripts as the Delve workflow — run them from the repo root:

```bash
cd /home/tcr6/conftamer
EV=contexttrack/events/caddy_test.jsonl   # or k8s_test.jsonl, prom.jsonl, ...

# Text summary
python3 contexttrack/analysis/group_by_context.py "$EV"

# Graph
python3 contexttrack/analysis/message_graph.py "$EV" --format dot | dot -Tsvg > graph.svg
```

In id-join mode, each `root context: id:N` group is one request/response exchange;
a group containing a `Request received` plus the `Request sent`/`Response received`
of a downstream call is a handler that made an outbound request (received→sent
causality). See [`message_graph`](analysis/message_graph.py) for node/edge details.

## Notes & gotchas

- **`GOTOOLCHAIN=local` on every invocation** — results in empty events file
- **Stale server** (Prometheus, Caddy) — Check with `ss -tlnp | grep 9090` (Prometheus)
  or `2999` (Caddy) and kill the stale PID.
- **`-p 1` for Caddy integration tests** — to avoid port collisions
- **`etcd` on `PATH`** (Kubernetes) — `framework.EtcdMain` calls
  `exec.LookPath("etcd")` before any test runs.
- **504 orphan events** (Kubernetes) — the
  `WithTimeoutForNonLongRunningRequests` filter in apiserver races the request
  handler against a wall-clock deadline. If you see a `resp sent ... 504` with no matching `req received`, up `RequestTimeout` in
  `staging/src/k8s.io/apiserver/pkg/server/config.go`.
- **Append-only output** — `rm` the file between isolated runs.
- **Libraries:** HTTP/1.x and bundled HTTP/2 are instrumented.
  If a test uses a mocked library, it won't work.