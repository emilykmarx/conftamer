// Shared constants, config, and helpers used across the contexttrack package.
package contexttrack

import (
	"fmt"

	"github.com/go-delve/delve/service/api"
)

// App tags for Breakpoint.App. "base" breakpoints hook stdlib net/http (and
// its HTTP/2 support) — the machinery present in any Go HTTP program, so
// they're always registered regardless of which target is being traced. The
// others hook code specific to one traced application, and are only
// registered when that app is requested.
const (
	AppBase       = "base"
	AppCaddy      = "caddy"
	AppPrometheus = "prometheus"
)

// Breakpoint describes one Delve breakpoint target.
type Breakpoint struct {
	Location string // function name, or "file:line" for the one case where no function boundary works
	Label    string // used in diagnostic output and log lines
	Package  string // import path Location resolves against — what a version bump of this dependency could shift
	App      string // AppBase, AppCaddy, or AppPrometheus — which traced application this is specific to
}

// Breakpoints maps a stable key to each HTTP hook point Delve instruments.
// SetHTTPBreakpointsFor (context_finder.go) loads this map directly, so
// adding a new hook point only requires adding an entry here — no new
// top-level variable, and no separate label/app to keep in sync at the call
// site.
var Breakpoints = map[string]Breakpoint{
	// Inbound request received (HTTP/1.x). Fires once per request before any
	// registered handlers. Takes *http.Request as an argument named `req`.
	"HTTPReceiveFunc": {
		Location: "net/http.(*ServeMux).ServeHTTP",
		Label:    "req-received",
		Package:  "net/http",
		App:      AppBase,
	},

	// Inbound request received by Caddy's HTTP server. Fires for all requests
	// handled by caddyhttp (i.e. the reverse proxy and any other Caddy routes),
	// which bypass net/http.ServeMux entirely. Takes *http.Request as `r`.
	"HTTPReceiveFuncCaddy": {
		Location: "github.com/caddyserver/caddy/v2/modules/caddyhttp.(*Server).ServeHTTP",
		Label:    "req-received-caddy",
		Package:  "github.com/caddyserver/caddy/v2/modules/caddyhttp",
		App:      AppCaddy,
	},

	// Inbound request received at the compiled-route boundary, one layer inside
	// HTTPReceiveFuncCaddy. Unlike the above, this also fires in unit tests that
	// call a route's handler directly (bypassing the real listener/ServeMux/
	// caddyhttp.Server entirely), since it's the seam the metrics middleware
	// wraps. Takes *http.Request as `r`.
	"HTTPReceiveFuncCaddyRoute": {
		Location: "github.com/caddyserver/caddy/v2/modules/caddyhttp.(*metricsInstrumentedRoute).ServeHTTP",
		Label:    "req-received-caddy-route",
		Package:  "github.com/caddyserver/caddy/v2/modules/caddyhttp",
		App:      AppCaddy,
	},

	// Inbound request received (HTTP/2, Go >= 1.27 bundled h2_bundle.go).
	// Parameters: rw *http2responseWriter, req *Request, handler func(ResponseWriter, *Request)
	"HTTPReceiveFuncH2Bundled": {
		Location: "net/http.(*http2serverConn).runHandler",
		Label:    "req-received-h2-bundled",
		Package:  "net/http",
		App:      AppBase,
	},

	// Inbound request received (HTTP/2, Go <= 1.26 external golang.org/x/net/http2).
	// Caddy calls http2.ConfigureServer, which installs this package's handler into
	// TLSNextProto["h2"], overriding the bundled one.
	"HTTPReceiveFuncH2": {
		Location: "golang.org/x/net/http2.(*serverConn).runHandler",
		Label:    "req-received-h2",
		Package:  "golang.org/x/net/http2",
		App:      AppBase,
	},

	// Outbound request sent. Performs the actual TCP write. Takes *http.Request.
	"HTTPSendFunc": {
		Location: "net/http.(*Transport).roundTrip",
		Label:    "req-sent",
		Package:  "net/http",
		App:      AppBase,
	},

	// Outbound response sent (HTTP/1.x). Server writes HTTP header by committing
	// to a status code. Takes w *net/http.response (unexported type).
	"HTTPResponseFunc": {
		Location: "net/http.(*response).WriteHeader",
		Label:    "resp-sent",
		Package:  "net/http",
		App:      AppBase,
	},

	// Outbound response sent (HTTP/2, Go >= 1.27 bundled h2_bundle.go).
	// Receiver: w *http2responseWriter; code int; request at w.rws.req.
	"HTTPResponseFuncH2Bundled": {
		Location: "net/http.(*http2responseWriter).WriteHeader",
		Label:    "resp-sent-h2-bundled",
		Package:  "net/http",
		App:      AppBase,
	},

	// Outbound response sent (HTTP/2, Go <= 1.26 external golang.org/x/net/http2).
	// Receiver: w *responseWriter; code int; request at w.rws.req.
	"HTTPResponseFuncH2": {
		Location: "golang.org/x/net/http2.(*responseWriter).WriteHeader",
		Label:    "resp-sent-h2",
		Package:  "golang.org/x/net/http2",
		App:      AppBase,
	},

	// Outbound response committed at the Caddy layer, one level above whatever
	// http.ResponseWriter it's wrapping. Fires even when that writer is a fake
	// (e.g. httptest.ResponseRecorder in unit tests), unlike HTTPResponseFunc.
	// Receiver: rr *responseRecorder; param: statusCode int. No direct req
	// reference on rr — FindContext resolves context by walking up to the
	// caller frame's *http.Request instead.
	"HTTPResponseFuncCaddy": {
		Location: "github.com/caddyserver/caddy/v2/modules/caddyhttp.(*responseRecorder).WriteHeader",
		Label:    "resp-sent-caddy",
		Package:  "github.com/caddyserver/caddy/v2/modules/caddyhttp",
		App:      AppCaddy,
	},

	// Inbound response received. Hooks net/http.redirectBehavior, called inside
	// (*Client).do for every valid HTTP response immediately after send() returns.
	// Network-level failures are not captured here.
	"HTTPRecvResponseFunc": {
		Location: "net/http.redirectBehavior",
		Label:    "resp-received",
		Package:  "net/http",
		App:      AppBase,
	},

	// Inbound request received by promhttp's metric-serving handler (the closure
	// returned by HandlerFor/HandlerForTransactional). Fires in promhttp's own
	// unit tests, which call handler.ServeHTTP directly against a bare
	// http.Request/httptest.ResponseRecorder pair — bypassing net/http.Server,
	// ServeMux, and any real listener entirely. Takes *http.Request as `req`.
	"HTTPReceiveFuncPromHTTP": {
		Location: "github.com/prometheus/client_golang/prometheus/promhttp.HandlerForTransactional.func1",
		Label:    "req-received-promhttp",
		Package:  "github.com/prometheus/client_golang/prometheus/promhttp",
		App:      AppPrometheus,
	},

	// Outbound response committed via httptest.ResponseRecorder, the fake
	// http.ResponseWriter used by promhttp's own unit tests (and Go unit tests
	// generally). The unexported writeHeader helper that ResponseRecorder.Write
	// calls on the first Write() of an unset response funnels through this
	// exported method too, so it reliably fires for both explicit WriteHeader
	// calls (e.g. http.Error's error paths) and the implicit 200 on first Write.
	// Receiver: rw *httptest.ResponseRecorder; param: code int. No req reference
	// on rw — FindContext resolves context by walking up to the caller frame's
	// *http.Request instead, same as HTTPResponseFuncCaddy.
	//
	// Caveat: for promhttp's success-path responses (any test that actually
	// gathers and encodes metrics, as opposed to erroring out early), the call
	// chain from here back up to HandlerForTransactional.func1's `req` passes
	// through github.com/prometheus/common/expfmt's encoder/bufio-flush closures.
	// Delve's stack unwinder hits a hard wall a few frames into that chain (it
	// stops at expfmt.NewEncoder.func7 regardless of requested depth — verified
	// by bumping StackDepth well past 50 with no change), so FindContext fails
	// to reach `req` and root_addr comes back empty for those events. Error-path
	// responses (e.g. MaxRequestsInFlight, Timeout) call WriteHeader directly
	// from HandlerForTransactional.func1 without going through the encoder, so
	// they resolve fine. See HTTPResponseFuncPromHTTPReturn for the success-path
	// fallback.
	//
	// Package is stdlib (net/http/httptest), not client_golang — a promhttp
	// version bump can't shift this one — but App is AppPrometheus because
	// this codebase only expects it to fire while tracing promhttp's tests.
	"HTTPResponseFuncRecorder": {
		Location: "net/http/httptest.(*ResponseRecorder).WriteHeader",
		Label:    "resp-sent-recorder",
		Package:  "net/http/httptest",
		App:      AppPrometheus,
	},

	// Fallback "response sent" hook for promhttp's success path, where
	// HTTPResponseFuncRecorder can't resolve context (see its comment). This is
	// a file:line location, not a function name — it targets the closing brace
	// of promhttp.HandlerForTransactional.func1 (i.e. the handler falling off
	// its own end, response fully written), where `req` is still in frame 0, so
	// context resolution needs no stack walk at all.
	//
	// Unlike every other breakpoint in this package, this one is pinned to an
	// exact line number in a specific dependency version (client_golang
	// v1.23.2's prometheus/promhttp/http.go). A version bump will shift it — it
	// fails loud (SetBreakpointsFor logs a WARNING and skips) rather than
	// silently mistracking, but it needs to be re-derived after any upgrade:
	// find the closing "}" of the func literal passed to http.HandlerFunc(...)
	// inside HandlerForTransactional, and confirm via FindLocation that the
	// resolved PC is non-zero and inside that function.
	"HTTPResponseFuncPromHTTPReturn": {
		Location: "promhttp/http.go:259",
		Label:    "resp-sent-promhttp-return",
		Package:  "github.com/prometheus/client_golang/prometheus/promhttp",
		App:      AppPrometheus,
	},
}

// Verbose controls whether diagnostic output is printed to the terminal.
// Set this before calling any other functions in this package.
var Verbose bool

const StackDepth = 50

// ShallowStackDepth is tried first; most contexts are found near the top of the stack.
const ShallowStackDepth = 8

var LoadCfg = api.LoadConfig{
	FollowPointers:     true,
	MaxVariableRecurse: 6,
	MaxStringLen:       512,
	MaxArrayValues:     32,
	MaxStructFields:    -1,
}

// ScanCfg is used when scanning frames for a context variable — we only need
// the type name, so we skip all recursion and value loading.
var ScanCfg = api.LoadConfig{
	FollowPointers:     false,
	MaxVariableRecurse: 0,
	MaxStringLen:       0,
	MaxArrayValues:     0,
	MaxStructFields:    0,
}

// vprintf prints only when Verbose is true.
func vprintf(format string, args ...any) {
	if Verbose {
		fmt.Printf(format, args...)
	}
}

// vprintln prints only when Verbose is true.
func vprintln(s string) {
	if Verbose {
		fmt.Println(s)
	}
}

// Concrete types to track for the context.Context interface.
var ContextTypes = map[string]bool{
	"context.Context":           true,
	"context.cancelCtx":         true,
	"*context.cancelCtx":        true,
	"context.timerCtx":          true,
	"*context.timerCtx":         true,
	"context.valueCtx":          true,
	"*context.valueCtx":         true,
	"context.emptyCtx":          true,
	"*context.emptyCtx":         true,
	"context.backgroundCtx":     true,
	"*context.backgroundCtx":    true,
	"context.todoCtx":           true,
	"*context.todoCtx":          true,
	"context.withoutCancelCtx":  true,
	"*context.withoutCancelCtx": true,
}
