"""
Printing and data-collection helpers for HTTP messages.
Each function prints the message to the terminal and returns its fields as a dict.
"""

from delve_client_rpc import *


def _eval_flat(client: DelveClient, goroutine_id: int, frame: int, expr: str) -> str:
    try:
        return flat_value(client.eval_variable(goroutine_id, frame, expr).get("Variable") or {})
    except Exception as e:
        return f"<error: {e}>"


def _eval_with_fallbacks(client, goroutine_id, expr) -> tuple[str, str]:
    """Try expr as-is; if it fails and starts with a known request variable name,
    retry with alternate names (r <-> req). Returns (resolved_expr, value)."""
    val = _eval_flat(client, goroutine_id, 0, expr)
    if not val.startswith("<error:"):
        return expr, val
    prefix, _, rest = expr.partition(".")
    alternates = {"r": ["req"], "req": ["r"]}.get(prefix, [])
    for alt in alternates:
        alt_expr = f"{alt}.{rest}"
        alt_val = _eval_flat(client, goroutine_id, 0, alt_expr)
        if not alt_val.startswith("<error:"):
            return alt_expr, alt_val
    return expr, val


def _print_and_collect(client, goroutine_id, header, exprs) -> dict:
    print(f"\n┌─ {header}")
    data = {}
    for expr in exprs:
        resolved_expr, val = _eval_with_fallbacks(client, goroutine_id, expr)
        data[resolved_expr] = val
        print(f"│  {resolved_expr:<26} = {val}")
    print("└──────────────────────────────────────────────────────────────")
    return data


def get_http_request_recvd(client: DelveClient, goroutine_id: int) -> dict:
    return _print_and_collect(client, goroutine_id,
        "HTTP Request (received by server) ─────────────────────────",
        ["r.Method", "r.URL.Path", "r.URL.RawQuery", "r.Header", "r.RemoteAddr", "r.Proto"])


def get_http_request_sent(client: DelveClient, goroutine_id: int) -> dict:
    return _print_and_collect(client, goroutine_id,
        "HTTP Request (message being sent) ─────────────────────────",
        ["req.Method", "req.URL.Scheme", "req.URL.Host", "req.URL.Path", "req.URL.RawQuery", "req.Header"])


def get_http_response_sent(client: DelveClient, goroutine_id: int) -> dict:
    return _print_and_collect(client, goroutine_id,
        "HTTP Response (message being sent, HTTP/1.x) ──────────────",
        ["code", "w.handlerHeader", "w.req.Method", "w.req.URL.Path", "w.req.URL.RawQuery"])


def get_http_response_sent_h2(client: DelveClient, goroutine_id: int) -> dict:
    # For HTTP/2, the receiver is *http2responseWriter and request fields
    # live at w.rws.req rather than w.req.
    return _print_and_collect(client, goroutine_id,
        "HTTP Response (message being sent, HTTP/2) ────────────────",
        ["code", "w.rws.handlerHeader", "w.rws.req.Method", "w.rws.req.URL.Path", "w.rws.req.URL.RawQuery"])


def get_http_response_recvd(client: DelveClient, goroutine_id: int) -> dict:
    print("\n┌─ HTTP Response (received) ───────────────────────────────────")
    all_vars = get_all_frame_vars(client, goroutine_id, 0)
    resp_var = next(
        (v for v in all_vars if v.get("type") in ("*net/http.Response", "net/http.Response")),
        None,
    )
    if resp_var is None:
        print("│  (no *http.Response variable found in frame 0)")
        print("└──────────────────────────────────────────────────────────────")
        return {}
    vname = resp_var.get("name", "")
    data = {}
    for field in ["Status", "StatusCode", "Proto", "Header"]:
        val = _eval_flat(client, goroutine_id, 0, f"{vname}.{field}")
        data[f"resp.{field}"] = val
        print(f"│  resp.{field:<21} = {val}")
    for field in ["Method", "URL.Host", "URL.Path", "URL.RawQuery"]:
        val = _eval_flat(client, goroutine_id, 0, f"ireq.{field}")
        data[f"ireq.{field}"] = val
        print(f"│  ireq.{field:<21} = {val}")
    print("└──────────────────────────────────────────────────────────────")
    return data
