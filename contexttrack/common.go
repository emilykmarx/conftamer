package contexttrack

import "github.com/go-delve/delve/service/api"

// Breakpoint function names

// Inbound request received (HTTP/1.x). Fires once per request before any
// registered handlers. Takes *http.Request as an argument named `req`.
const HTTPReceiveFunc = "net/http.(*ServeMux).ServeHTTP"

// Inbound request received (HTTP/2, Go >= 1.27 bundled h2_bundle.go).
// Parameters: rw *http2responseWriter, req *Request, handler func(ResponseWriter, *Request)
const HTTPReceiveFuncH2Bundled = "net/http.(*http2serverConn).runHandler"

// Inbound request received (HTTP/2, Go <= 1.26 external golang.org/x/net/http2).
// Caddy calls http2.ConfigureServer, which installs this package's handler into
// TLSNextProto["h2"], overriding the bundled one.
const HTTPReceiveFuncH2 = "golang.org/x/net/http2.(*serverConn).runHandler"

// Outbound request sent. Performs the actual TCP write. Takes *http.Request.
const HTTPSendFunc = "net/http.(*Transport).roundTrip"

// Outbound response sent (HTTP/1.x). Server writes HTTP header by committing
// to a status code. Takes w *net/http.response (unexported type).
const HTTPResponseFunc = "net/http.(*response).WriteHeader"

// Outbound response sent (HTTP/2, Go >= 1.27 bundled h2_bundle.go).
// Receiver: w *http2responseWriter; code int; request at w.rws.req.
const HTTPResponseFuncH2Bundled = "net/http.(*http2responseWriter).WriteHeader"

// Outbound response sent (HTTP/2, Go <= 1.26 external golang.org/x/net/http2).
// Receiver: w *responseWriter; code int; request at w.rws.req.
const HTTPResponseFuncH2 = "golang.org/x/net/http2.(*responseWriter).WriteHeader"

// Inbound response received. Hooks net/http.redirectBehavior, called inside
// (*Client).do for every valid HTTP response immediately after send() returns.
// Network-level failures are not captured here.
const HTTPRecvResponseFunc = "net/http.redirectBehavior"

const StackDepth = 50

var LoadCfg = api.LoadConfig{
	FollowPointers:     true,
	MaxVariableRecurse: 6,
	MaxStringLen:       512,
	MaxArrayValues:     32,
	MaxStructFields:    -1,
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
