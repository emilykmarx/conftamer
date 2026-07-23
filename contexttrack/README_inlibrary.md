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

## Analyzing the output

Same scripts as the Delve workflow — run them from the repo root:

```bash
cd /home/tcr6/conftamer
EV=contexttrack/events/prom.jsonl

# Text summary: messages grouped by shared context (the potential graph edges)
python3 contexttrack/analysis/group_by_context.py "$EV"

# Graph
python3 contexttrack/analysis/message_graph.py "$EV" --format dot | dot -Tsvg > graph.svg
```

In id-join mode, each `root context: id:N` group is one request/response exchange;
a group containing a `Request received` plus the `Request sent`/`Response received`
of a downstream call is a handler that made an outbound request (received→sent
causality). See [`message_graph`](analysis/message_graph.py) for node/edge details.

## Notes & gotchas

- **`GOTOOLCHAIN=local` on every invocation** — the single most common failure mode
  (an empty `prom.jsonl`) is forgetting it.
- **Stale server on `:9090`** — same gotcha as the Delve workflow. A pre-existing
  Prometheus may already own `:9090`; the instrumented one then fails to bind and
  exits, and a readiness `curl` silently hits the *stale, uninstrumented* server,
  leaving `prom.jsonl` empty. Check with `ss -tlnp | grep 9090`, and use a free port
  (e.g. `:19090`) rather than killing a server you didn't start.
- **Append-only output** — `rm` the file between isolated runs.
- **`/usr/local/go` is untouched** — normal Go work is unaffected; only commands
  that explicitly use `/home/tcr6/go-conftamer/bin/go` get the instrumented library.
- **Scope:** HTTP/1.x and bundled HTTP/2 are instrumented. External
  `golang.org/x/net/http2` (module cache) is not reachable via the clone; Prometheus's
  standard client/server paths don't need it.
- **Join-key comparison:** to compare a new run against a pre-existing Delve-era
  `events.jsonl`, regenerate with `CONFTAMER_JOIN=addr` so both use heap addresses;
  the default `id:N` keys are intentionally not address-comparable.
- Per `CLAUDE.md`: graph edges mean "shares a tracked context," not "causes."
