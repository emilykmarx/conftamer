"""
Delve client that tracks context propagation to associate
each received HTTP message with a subsequent sent HTTP message.

This logic is specific to HTTP because of:
    1. Where we set breakpoints
    2. How we find Context (via http.Request if no explicit Context variable)

Usage:

Terminal 1: start target under delve (disable inlining for net/http)
    dlv debug --headless --listen=:2345 --api-version=2  --build-flags="-gcflags=net/http=-l" .
    or:
        dlv test --headless --listen=:2345 --api-version=2  --build-flags="-gcflags=net/http=-l" [directory] [options]

Terminal 2: run this script
    python3 delve_client/delve_client.py [--output events.jsonl]

Terminal 3 (for the ContextBlog example): make a request to the target server
    curl "http://localhost:8080/search?q=golang"

"""

import argparse
import json
import sys
from dataclasses import dataclass

from delve_client_rpc import *
from common import *
from delve_client_fmt import *


@dataclass
class HttpBreakpointIDs:
    req_receive_bp_ids:    set
    req_receive_h2_bp_ids: set
    req_send_bp_ids:       set
    resp_send_bp_ids:      set
    resp_send_h2_bp_ids:   set
    resp_recv_bp_ids:      set


def set_http_breakpoints(client: DelveClient) -> HttpBreakpointIDs:
    # For HTTP/2, try both the external golang.org/x/net/http2 package
    # (active on Go <= 1.26 when Caddy calls http2.ConfigureServer) and the
    # bundled h2_bundle.go version (active on Go >= 1.27).  set_breakpoints_for
    # prints a WARNING and returns an empty set if a function is not found, so
    # whichever copy is absent in this binary is silently skipped.
    return HttpBreakpointIDs(
        req_receive_bp_ids    = set_breakpoints_for(client, HTTP_RECEIVE_FUNC,             "req-received"),
        req_receive_h2_bp_ids = (set_breakpoints_for(client, HTTP_RECEIVE_FUNC_H2,         "req-received-h2")
                               | set_breakpoints_for(client, HTTP_RECEIVE_FUNC_H2_BUNDLED, "req-received-h2-bundled")),
        req_send_bp_ids       = set_breakpoints_for(client, HTTP_SEND_FUNC,                "req-sent"),
        resp_send_bp_ids      = set_breakpoints_for(client, HTTP_RESPONSE_FUNC,            "resp-sent"),
        resp_send_h2_bp_ids   = (set_breakpoints_for(client, HTTP_RESPONSE_FUNC_H2,        "resp-sent-h2")
                               | set_breakpoints_for(client, HTTP_RESPONSE_FUNC_H2_BUNDLED,"resp-sent-h2-bundled")),
        resp_recv_bp_ids      = set_breakpoints_for(client, HTTP_RECV_RESPONSE_FUNC,       "resp-received"),
    )


# Expressions that follow a parent-context pointer from a given context expression.
_PARENT_POINTERS = [
    lambda cur: f"({cur}).(*context.valueCtx).Context",
    lambda cur: f"({cur}).(*context.cancelCtx).Context",
    lambda cur: f"({cur}).(*context.timerCtx).cancelCtx.Context",
]

# Container types whose embedded context can be reached via a known field path.
_CTX_CONTAINERS = [
    ({"*net/http.Request",               "net/http.Request"},               lambda n: f"{n}.ctx"),
    ({"*net/http.response",              "net/http.response"},              lambda n: f"{n}.req.ctx"),
    ({"*net/http.requestAndChan",        "net/http.requestAndChan"},        lambda n: f"{n}.treq.Request.ctx"),
    # HTTP/2 response writer (bundled h2_bundle.go, Go >= 1.27)
    ({"*net/http.http2responseWriter",                  "net/http.http2responseWriter"},                  lambda n: f"{n}.rws.req.ctx"),
    # HTTP/2 response writer (external x/net/http2, Go <= 1.26)
    ({"*golang.org/x/net/http2.responseWriter",         "golang.org/x/net/http2.responseWriter"},         lambda n: f"{n}.rws.req.ctx"),
]


def _walk_context_chain(
        client: DelveClient, goroutine_id: int, frame_id: int,
        expr: str, indent: str = "   ") -> str:
    """Walk the context parent chain; print and return the root address as a hex string."""
    cur = expr
    for _ in range(20):
        for get_parent in _PARENT_POINTERS:
            try:
                next_expr = get_parent(cur)
                client.eval_variable(goroutine_id, frame_id, next_expr)
                cur = next_expr
                break
            except Exception:
                continue
        else:
            try:
                v = client.eval_variable(goroutine_id, frame_id, cur).get("Variable") or {}
                addr = v.get("addr", 0)
                addr_str = f"0x{addr:x}" if addr else "?"
                print(f"{indent}root context @ {addr_str}")
                return addr_str
            except Exception:
                return "?"
    return "?"


def _find_context_in_frame(
        client: DelveClient, goroutine_id: int, frame_id: int, func_name: str,
) -> dict | None:
    """Search one stack frame for a context; print and return what's found, or None."""
    all_vars = get_all_frame_vars(client, goroutine_id, frame_id)

    # Strategy 1: explicit context.Context variable
    for v in all_vars:
        if v.get("type", "").lstrip("*") in CONTEXT_TYPES:
            name = v.get("name")
            print(f"Context variable found: {name}  ({v.get('type')})")
            print_variable(v, "  ", "    ")
            root_addr = _walk_context_chain(client, goroutine_id, frame_id, name)
            return {"source": name, "type": v.get("type"), "root_addr": root_addr}

    # Strategies 2–4: find context through a known container type
    for types, make_expr in _CTX_CONTAINERS:
        for v in all_vars:
            if v.get("type", "") in types:
                expr = make_expr(v.get("name", ""))
                try:
                    ctx_v = client.eval_variable(goroutine_id, frame_id, expr).get("Variable") or {}
                    if ctx_v.get("type"):
                        print("│")
                        print(f"└─ Context from {expr} in frame {frame_id}: {func_name}")
                        print(f"   type: {ctx_v.get('type')}")
                        root_addr = _walk_context_chain(client, goroutine_id, frame_id, expr)
                        return {"source": expr, "type": ctx_v.get("type"), "root_addr": root_addr}
                except Exception:
                    pass

    return None


def find_context(client: DelveClient, goroutine_id: int) -> dict | None:
    """
    Search the stack for a context.Context by walking up to STACK_DEPTH frames.
    Prints the backtrace and returns a dict with the context info found.

    Strategies (tried per frame, in order):
      1. Explicit context.Context variable
      2. Context from *http.Request.ctx
      3. Context from *http.response.req.ctx  (server-side)
      4. Context from http.requestAndChan.treq.Request.ctx  (client-side)
    """
    print("\n┌─ Stack backtrace (searching for context.Context) ────────────")
    try:
        frames = client.stacktrace(goroutine_id).get("Locations") or []
    except Exception as e:
        print(f"│  stacktrace error: {e}")
        print("└──────────────────────────────────────────────────────────────")
        return None

    frames_visited = []
    for i, frame in enumerate(frames):
        func_name = (frame.get("function") or {}).get("name", "<unknown>")
        print(f"│  [{i:2d}] {func_name}")
        print(f"│       {frame.get('file', '')}:{frame.get('line', 0)}")
        frames_visited.append({"index": i, "func": func_name,
                                "file": frame.get("file", ""), "line": frame.get("line", 0)})
        ctx = _find_context_in_frame(client, goroutine_id, i, func_name)
        if ctx is not None:
            print("└──────────────────────────────────────────────────────────────")
            ctx["frames_searched"] = frames_visited
            return ctx

    print("└──────────────────────────────────────────────────────────────")
    return {"frames_searched": frames_visited}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect context and message on every HTTP send and receive"
    )
    parser.add_argument("--addr", default="localhost:2345",
                        help="Delve headless server address (default: localhost:2345)")
    parser.add_argument("--output", metavar="FILE",
                        help="JSON Lines file to append events to (one object per line)")
    args = parser.parse_args()
    host, _, port_str = args.addr.rpartition(":")

    try:
        client = DelveClient(host or "localhost", int(port_str))
    except OSError as e:
        sys.exit(f"Cannot connect to Delve: {e}\n"
                 "Is Delve running?  "
                 "dlv debug --headless --listen=:2345 --api-version=2 .")

    out_file = open(args.output, "a") if args.output else None

    print("Setting breakpoints:")
    http_bp_ids = set_http_breakpoints(client)
    print("Waiting for HTTP events… (Ctrl-C to stop)\n")

    # Map each breakpoint set to its label and handler.
    # HTTP/2 variants use the same "Request received" / "Response sent" labels
    # but different data-extraction functions because the internal types differ.
    bp_handlers = [
        (http_bp_ids.req_receive_bp_ids,    "Request received",  get_http_request_recvd),
        (http_bp_ids.req_receive_h2_bp_ids, "Request received",  get_http_request_recvd),   # req param identical
        (http_bp_ids.req_send_bp_ids,       "Request sent",      get_http_request_sent),
        (http_bp_ids.resp_send_bp_ids,      "Response sent",     get_http_response_sent),
        (http_bp_ids.resp_send_h2_bp_ids,   "Response sent",     get_http_response_sent_h2),
        (http_bp_ids.resp_recv_bp_ids,      "Response received", get_http_response_recvd),
    ]

    while True:
        try:
            state = client.command("continue").get("State") or {}
        except KeyboardInterrupt:
            print("\nStopping.")
            if out_file:
                out_file.close()
            break
        except Exception as e:
            sys.exit(f"Error continuing execution: {e}")

        if state.get("exited"):
            print(f"\nProcess exited (status {state.get('exitStatus', '?')})")
            break
        if err := state.get("Err"):
            print(f"Debugger error: {err}", file=sys.stderr)
            break

        thread = state.get("currentThread") or {}
        goroutine_id = thread.get("goroutineID") or -1
        bp_id = (thread.get("breakPoint") or {}).get("id")

        kind, handler = next(
            ((label, fn) for ids, label, fn in bp_handlers if bp_id in ids),
            ("Unknown", None),
        )

        print("╔══════════════════════════════════════════════════════════════╗")
        print(f"║  HTTP {kind} — goroutine {goroutine_id}, thread {thread.get('id', '?')}")
        print(f"║  {thread.get('file', '?')}:{thread.get('line', '?')}")
        print("╚══════════════════════════════════════════════════════════════╝")

        try:
            msg_data = handler(client, goroutine_id) if handler else None
        except Exception as e:
            print(f"WARNING: message handler raised: {e}", file=sys.stderr)
            msg_data = {"error": str(e)}

        try:
            ctx_data = find_context(client, goroutine_id)
        except Exception as e:
            print(f"WARNING: find_context raised: {e}", file=sys.stderr)
            ctx_data = {"error": str(e)}

        if out_file:
            event = {
                "kind":         kind,
                "goroutine_id": goroutine_id,
                "thread_id":    thread.get("id"),
                "file":         thread.get("file"),
                "line":         thread.get("line"),
                "message":      msg_data,
                "context":      ctx_data,
            }
            out_file.write(json.dumps(event) + "\n")
            out_file.flush()

        print()


if __name__ == "__main__":
    main()
