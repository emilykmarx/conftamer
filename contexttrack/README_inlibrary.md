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

**`-count=1` is mandatory.** `go test` caches results; a cached package is **not
re-executed**, so its binary never runs and **no events are produced**. An empty or
absent output file after a `go test` run is most often a missing `-count=1`.

**Confirming the clone is linked.** With `CONFTAMER_EVENTS` set, every binary built
with this toolchain prints one line to stderr at startup:

```
conftamer: enabled — writing "/…/prom_test.jsonl" (join=id)
```

(or `conftamer: … open failed: …` if the output directory is missing). Under
`go test` this line only shows for packages run with `-v`, but the output file is
created **eagerly** as soon as any instrumented binary starts. So: file appears
(even empty) → clone linked, just no HTTP in those tests; file never appears with
`-count=1` → the instrumented `net/http` was not linked (wrong `go`, a hermetic/
`make` build, or a bad `CONFTAMER_EVENTS` dir — run `-v` to see the reason).

## Targets other than Prometheus (Caddy, Kubernetes)

The clone instruments **base `net/http` + the bundled `h2_bundle.go`** only, so
other targets can legitimately produce few or no events:

- **Caddy** configures HTTP/2 via the **external** `golang.org/x/net/http2` (module
  cache — not patchable by the GOROOT clone) and funnels requests through its own
  `caddyhttp.(*Server).ServeHTTP`, not `net/http.serverHandler.ServeHTTP`. With
  Caddy's automatic-HTTPS default, nearly all traffic is HTTP/2 and **no base hook
  fires**. Force plaintext HTTP/1 (`curl --http1.1 http://…`) to hit the
  instrumented funnel. Full coverage needs the Caddy-specific / external-h2 hooks
  the Delve build had (`common.go`), which are out of scope here.
- **Kubernetes** `make`/`hack/*` builds fetch their **own** Go via `.go-version`,
  ignoring the clone; and a real cluster runs prebuilt container images where the
  clone and `CONFTAMER_EVENTS` don't apply. Only a direct
  `~/go-conftamer/bin/go test -count=1 <pkgs>` (e.g. client-go / apiserver packages
  using `httptest`) is instrumented.

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

### Don't run `go test ./...` from the k8s root

A naive `~/go-conftamer/bin/go test -count=1 ./...` from `~/kubernetes` reports
~790 failing packages — but almost all are **`[build failed]`**, not test failures.
Hundreds of k8s packages don't compile standalone (generated code, build tags,
cgo, test-only infra), and much of the real HTTP code lives in **separate staging
modules** that the root module's `./...` doesn't even include. This is inherent to
k8s's build layout and **unrelated to the instrumentation** — a build failure means
the package didn't compile, which the added `net/http` logging cannot cause (if it
had broken `net/http`, *every* package would fail, not ~57%). Confirm with:

```bash
grep -c '\[build failed\]' "$LOG"
```

So don't chase a clean `./...`. Scope to packages that build and do HTTP instead —
either the staging modules (A, no etcd) or the integration packages (B, needs etcd).

### A. Staging modules (no etcd, builds cleanly)

The client/server HTTP code lives under `staging/src/k8s.io/*`, each its own Go
module. `cd` into one and run its tests — these compile cleanly and emit plenty of
events. `client-go` is the easiest (httptest-based, no etcd):

```bash
cd ~/kubernetes/staging/src/k8s.io/client-go
EV=~/conftamer/contexttrack/events/k8s_clientgo.jsonl
rm -f "$EV"

GOTOOLCHAIN=local CONFTAMER_EVENTS="$EV" \
  ~/go-conftamer/bin/go test -count=1 ./transport/... ./rest/... ./tools/...
# verified: ~22 packages ok, 0 build failures, ~950 events (api_id: k8s.io)
```

`k8s.io/apiserver` is the other HTTP-rich module (some of its packages need etcd —
see B).

### B. Integration packages (need etcd)

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
- **k8s `./...` "failures" are build failures, not test failures** — expected under
  naive `go test ./...` and unrelated to instrumentation; scope to staging modules
  or integration packages instead (see *Running Kubernetes tests*).
- **504 orphan events** (Kubernetes) — the
  `WithTimeoutForNonLongRunningRequests` filter in apiserver races the request
  handler against a wall-clock deadline. If you see a `resp sent ... 504` with no matching `req received`, up `RequestTimeout` in
  `staging/src/k8s.io/apiserver/pkg/server/config.go`.
- **Append-only output** — `rm` the file between isolated runs.
- **Libraries:** HTTP/1.x and bundled HTTP/2 are instrumented.
  If a test uses a mocked library, it won't work.