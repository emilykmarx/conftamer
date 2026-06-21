"""
Constants
"""

# --------------------------------------------
# Breakpoints
# --------------------------------------------

# Inbound request received (HTTP/1.x). Fires once per request
# before any registered handlers. When this is invoked,
# initial request context is already set.
# Takes *http.Request as an argument named `req`.
HTTP_RECEIVE_FUNC = "net/http.(*ServeMux).ServeHTTP"
# HTTP_RECEIVE_FUNC_2 = "net/http.(*ServeMux).ServeHTTP"

# Inbound request received (HTTP/2, Go >= 1.27 bundled h2_bundle.go).
# Only active when golang.org/x/net/http2 is NOT overriding TLSNextProto.
# Parameters: rw *http2responseWriter, req *Request, handler func(ResponseWriter, *Request)
HTTP_RECEIVE_FUNC_H2_BUNDLED = "net/http.(*http2serverConn).runHandler"

# Inbound request received (HTTP/2, Go <= 1.26 external golang.org/x/net/http2).
# Caddy calls golang.org/x/net/http2.ConfigureServer, which installs this
# package's handler into TLSNextProto["h2"], overriding the bundled one.
# Parameters: rw *responseWriter, req *http.Request, handler func(...)
HTTP_RECEIVE_FUNC_H2 = "golang.org/x/net/http2.(*serverConn).runHandler"

# Outbound request sent. Performs the actual TCP write.
# takes *http.Request as an argument.
HTTP_SEND_FUNC = "net/http.(*Transport).roundTrip"

# Outbound response sent (HTTP/1.x). Server writes HTTP header by
# committing to a status code.
# Takes `w *net/http.response` (unexported type), which
# contains code and original request.
HTTP_RESPONSE_FUNC = "net/http.(*response).WriteHeader"

# Outbound response sent (HTTP/2, Go >= 1.27 bundled h2_bundle.go).
# Receiver: w *http2responseWriter; code int; request at w.rws.req.
HTTP_RESPONSE_FUNC_H2_BUNDLED = "net/http.(*http2responseWriter).WriteHeader"

# Outbound response sent (HTTP/2, Go <= 1.26 external golang.org/x/net/http2).
# Receiver: w *responseWriter; code int; request at w.rws.req.
HTTP_RESPONSE_FUNC_H2 = "golang.org/x/net/http2.(*responseWriter).WriteHeader"

# Inbound response received.
# Hooks net/http.redirectBehavior, which is called inside (*Client).do for
# every valid HTTP response (200, 4xx, 5xx, …) immediately after send()
# returns. It takes resp *Response as an explicit argument, so the value is
# live at function entry and always readable — no return-value / DWARF
# dead-range issues. Note: network-level failures (connection refused,
# timeout) cause an early return from (*Client).do before this call, so
# those are not captured here.
HTTP_RECV_RESPONSE_FUNC = "net/http.redirectBehavior"


# --------------------------------------------
# Delve configs
# --------------------------------------------

# TODO: what's a reasonable value for this?
# Used to stacktrace the context propagation path.
STACK_DEPTH = 50

# Controls how deeply to inspect variables
LOAD_CFG = {
    # If variable is a pointer, dereference it
    "FollowPointers":     True,
    # Nested structs/interfaces
    "MaxVariableRecurse": 6,
    # Truncate string values
    "MaxStringLen":       512,
    # Truncate array/slice contents
    "MaxArrayValues":     32,
    # Show all struct fields
    "MaxStructFields":    -1,
}

# Concrete types to track for the context.Context interface.
# TODO is this a reasonable set?
CONTEXT_TYPES = {
    "context.Context",
    "context.cancelCtx",        "*context.cancelCtx",
    "context.timerCtx",         "*context.timerCtx",
    "context.valueCtx",         "*context.valueCtx",
    "context.emptyCtx",         "*context.emptyCtx",
    "context.backgroundCtx",    "*context.backgroundCtx",
    "context.todoCtx",          "*context.todoCtx",
    "context.withoutCancelCtx", "*context.withoutCancelCtx",
}