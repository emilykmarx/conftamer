# Context-Message Tracking

Compile context and message tracing logic directly into a cloned copy of the
Go standard library. Any program built with this toolchain produces a `jsonl`
file that can be used with the scripts in `analysis/`.

**Goal** of this is to infer causal relationships between HTTP messages,
i.e., "receiving this request led to sending this follow-on request."
We define this control flow influence as two messages that share the same
"root" context (the definition of "root" may be a bit library-specific).

**TODO**: Not confident in a fair amount of this ("API ID" logic,
where we're assigning context IDs, and where we're logging).

**TODO**: Different approach to context ID that could allow us to correlate across tests?

## How to Use

### Modify Go

Apply [`go-inlibrary.patch`](go-inlibrary.patch) to a cloned copy of Go.
(I directly copied the contents of `/usr/local/go` into `~/go-conftamer/`
and applied the patch there.)

Contexts are correlated by a monotonic ID stamped at an HTTP request's origin and
inherited down the context chain.
An earlier approach instead walked the context's parent
chain to a shared root heap address; it's no longer used (false positives
from heap-address reuse, more vulnerable to custom types) but is preserved as
[`go-inlibrary-optional.patch`](go-inlibrary-optional.patch).

### Set Environment Variables

- **`GOTOOLCHAIN=local`** — Without it, Go's `auto` toolchain may download
  a new fork of Go.
- **`CONFTAMER_EVENTS=/path/to/output.jsonl`** — where events are written.

Note: when running `go test`, use `-count=1` as an argument to make sure that cached
tests get re-run. An empty output file may be caused by a missing `-count=1`.

### Output

The file is opened `O_APPEND`.
Delete (or point `CONFTAMER_EVENTS` at a fresh path) between runs you want to analyze in isolation.

Each line looks something like this:

```json
{"kind":"Request sent","goroutine_id":435,"file":".../net/http/transport.go","line":599,
 "message":{"req.Method":"GET","req.URL.Host":"127.0.0.1:9090","req.URL.Path":"/metrics","req.URL.RawQuery":""},
 "context":{"source":"req.Context()","type":"context.Context","context_id":"id:7"},
 "request_id":{"method":"GET","host":"127.0.0.1:9090","path":"/metrics"},"api_id":"github.com/prometheus"}
```

Use `analysis/group_by_context.py` to see context groups and `analysis/message_graph.py`
to generate the full, directed grah.

# Running Tests

## Prometheus

All tests:

```bash
cd ~/prometheus-src # or Prometheus directory
unset GOROOT   # a .bashrc-exported GOROOT silently reverts to the vanilla stdlib
export GOTOOLCHAIN=local
export CONFTAMER_EVENTS=~/conftamer/contexttrack/events/prom_test.jsonl
rm -f "$CONFTAMER_EVENTS"

~/go-conftamer/bin/go test -count=1 -v ./...
```

Or, just one test, e.g.:

```bash
~/go-conftamer/bin/go test ./scrape/ -run TestTargetScraperScrapeOK -count=1 -v
```

**`-count=1`**: `go test` caches results; a cached package is not re-executed by
default. This forces each test to run once.

**`-v`**: to see output from the test.

**Confirming the clone is linked**: Check for this line:

```
conftamer: enabled — writing "/.../prom_test.jsonl"
```

(or `conftamer: ... open failed: ...` if the output directory is missing).

## Caddy

**TODO**. Caddy seems to configure HTTP/2 via external `golang.org/x/net/http2`
module cache ad sends requests through its internal `caddyhttp.(*Server).ServeHTTP`.
So, the current hooks aren't firing.

All integration tests:

```bash
cd ~/caddy
export GOTOOLCHAIN=local
export CONFTAMER_EVENTS=~/conftamer/contexttrack/events/caddy_test.jsonl
rm -f "$CONFTAMER_EVENTS"
~/go-conftamer/bin/go test -count=1 -p 1 ./caddytest/integration/
```

Note: use `-p 1` to disable parallelization.
Each integration test starts a Caddy server on the same port, so we can't
actually execute parallel test processes.

Or, just one test, e.g.:

```bash
~/go-conftamer/bin/go test -count=1 -p 1 ./caddytest/integration/ \
  -run TestReverseProxySubroutes
```

Unit tests:

```bash
~/go-conftamer/bin/go test -count=1 ./modules/caddyhttp/reverseproxy/
```

## Kubernetes

**TODO**. I think that `make`/`hack1/*` builds and fetches a new(?) Go.
I'm not totally clear if this messes us up.

**TODO**. Running `go tests ./...` from the k8s root results in a lot of build erros.
I'm not totally clear why. I think that it's unrelated to us.

I've gotten events from the following subdirectories; I'm sure I'm missing some other
modules that we should run on.

### Staging modules (no etcd)

```bash
cd ~/kubernetes/staging/src/k8s.io/client-go
export GOTOOLCHAIN=local
export CONFTAMER_EVENTS=~/conftamer/contexttrack/events/k8s_test.jsonl
rm -f "$CONFTAMER_EVENTS"

~/go-conftamer/bin/go test -count=1 ./transport/... ./rest/... ./tools/...
```

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
export GOTOOLCHAIN=local
export CONFTAMER_EVENTS=~/conftamer/contexttrack/events/k8s_test.jsonl
rm -f "$CONFTAMER_EVENTS"

~/go-conftamer/bin/go test -count=1 ./test/integration/endpoints/
```

Or, just one test, e.g.:

```bash
~/go-conftamer/bin/go test -count=1 ./test/integration/endpoints/ -run TestEndpointWithMultiplePods
```

`./test/integration/endpoints` (apiserver) is the primary package.

**TODO**: other packages under `./test/integration/` might have other prereqs.

# Analyzing Output

Run scripts from `analysis/`

```bash
cd /home/tcr6/conftamer
EV=contexttrack/events/caddy_test.jsonl   # or k8s_test.jsonl, prom.jsonl, ...

# Text summary
python3 contexttrack/analysis/group_by_context.py "$EV"

# Graph
python3 contexttrack/analysis/message_graph.py "$EV" --format dot | dot -Tsvg > graph.svg
```

See [`message_graph`](analysis/message_graph.py) for node/edge details.

## Notes & gotchas

- **Check `GOROOT`** — if the shell exports
  `GOROOT` (e.g. `.bashrc` lines added by version managers like `g`), the patched
  `~/go-conftamer/bin/go` compiles against that stdlib instead of its own patched
  one. Run `unset GOROOT` first, and verify with
  `~/go-conftamer/bin/go env GOROOT`.
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
- **First run after (re)building patched `go` is slow** — any changes to the stdlib
  require a full rebuild. `go test ./...` on a large module (e.g. all of Prometheus)
  recompiles the whole stdlib + module graph from scratch before the first test binary starts,
   which can take several minutes with no output in the meantime. Subsequent runs reuse the cache.
- **Libraries:** HTTP/1.x and bundled HTTP/2 are instrumented.
  If a test uses a mocked library, it won't work.
- **`-count 1`** - run all tests, even if cached.
