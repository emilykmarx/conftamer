"""
Generic methods for invoking Delve RPC server methods and interpreting outputs.
"""

from common import LOAD_CFG, STACK_DEPTH

import json
import socket


class DelveClient:
    """Wrapper around Delve's JSON-RPC2 API."""

    def __init__(self, host: str, port: int):
        print(f"Connecting to Delve at {host}:{port}…")
        self._id = 0
        self._sock = socket.create_connection((host, port))
        self._sock.settimeout(None)
        self._reader = self._sock.makefile("rb")

    def _call(self, method: str, params: dict) -> dict:
        self._id += 1
        req = {"jsonrpc": "2.0", "method": method, "params": [params], "id": self._id}
        self._sock.sendall(json.dumps(req, separators=(",", ":")).encode() + b"\n")
        line = self._reader.readline()
        if not line:
            raise ConnectionError("Delve closed the connection")
        resp = json.loads(line)
        if resp.get("error"):
            raise RuntimeError(f"Delve RPC error [{method}]: {resp['error']}")
        return resp.get("result") or {}

    def find_location(self, loc_string: str) -> dict:
        return self._call("RPCServer.FindLocation", {
            "Scope": {"GoroutineID": -1, "Frame": 0, "DeferredCall": 0},
            "Loc":   loc_string,
            "IncludeNonExecutableLines": False,
            "SubstitutePathRules":       None,
        })

    def create_breakpoint(self, addr: int) -> dict:
        return self._call("RPCServer.CreateBreakpoint", {
            "Breakpoint":   {"addr": addr},
            "TemplateName": "",
        })

    def command(self, name: str, goroutine_id: int = -1) -> dict:
        return self._call("RPCServer.Command", {
            "Name":        name,
            "GoroutineID": goroutine_id,
        })

    def stacktrace(self, goroutine_id: int, depth: int = STACK_DEPTH) -> dict:
        return self._call("RPCServer.Stacktrace", {
            "Id":     goroutine_id,
            "Depth":  depth,
            "Full":   False,
            "Defers": False,
            "Opts":   0,
            "Cfg":    LOAD_CFG,
        })

    def list_function_args(self, goroutine_id: int, frame: int) -> dict:
        return self._call("RPCServer.ListFunctionArgs", {
            "Scope": {"GoroutineID": goroutine_id, "Frame": frame, "DeferredCall": 0},
            "Cfg":   LOAD_CFG,
        })

    def list_local_vars(self, goroutine_id: int, frame: int) -> dict:
        return self._call("RPCServer.ListLocalVars", {
            "Scope": {"GoroutineID": goroutine_id, "Frame": frame, "DeferredCall": 0},
            "Cfg":   LOAD_CFG,
        })

    def eval_variable(self, goroutine_id: int, frame: int, expr: str) -> dict:
        return self._call("RPCServer.Eval", {
            "Scope": {"GoroutineID": goroutine_id, "Frame": frame, "DeferredCall": 0},
            "Expr":  expr,
            "Cfg":   LOAD_CFG,
        })


def set_breakpoints_for(client: DelveClient, func_name: str, name: str) -> set:
    locs = client.find_location(func_name).get("Locations") or []
    if not locs:
        print(f"  WARNING: no locations found for {func_name!r} — skipping")
        return set()
    ids = set()
    for loc in locs:
        addr = loc.get("pc", 0)
        bp = client.create_breakpoint(addr).get("Breakpoint") or {}
        bp_id = bp.get("id")
        if bp_id is None:
            print(f"  WARNING: [{name}] breakpoint created but Delve returned no id for 0x{addr:x}")
        else:
            ids.add(bp_id)
        print(f"  [{name}] Breakpoint {bp_id} at "
              f"{bp.get('file')}:{bp.get('line')} (0x{addr:x}) for {func_name!r}")
    return ids


def get_all_frame_vars(client: DelveClient, goroutine_id: int, frame: int) -> list:
    result = []
    try:
        result.extend(client.list_function_args(goroutine_id, frame).get("Args") or [])
    except Exception:
        pass
    try:
        result.extend(client.list_local_vars(goroutine_id, frame).get("Variables") or [])
    except Exception:
        pass
    return result


def flat_value(v: dict) -> str:
    """One-line summary of a Delve variable."""
    if val := v.get("value", ""):
        return val
    children = v.get("children") or []
    if not children:
        return f"({v.get('type', '?')})"
    parts = [f"{c.get('name')}:{c.get('value', '…')}" for c in children if c.get("value")]
    if not parts:
        return f"({v.get('type', '?')} …)"
    snippet = " ".join(parts[:5])
    if len(parts) > 5:
        snippet += " …"
    return "{" + snippet + "}"


def print_variable(v: dict, prefix: str, child_prefix: str, depth: int = 0) -> None:
    """Recursively print a Delve variable tree."""
    if v is None or depth > 6:
        return
    name, typ, val = v.get("name", ""), v.get("type", ""), v.get("value", "")
    children = v.get("children") or []
    type_str = f" ({typ})" if typ else ""
    if val:
        print(f"{prefix}{name}{type_str} = {val}")
    elif children:
        print(f"{prefix}{name}{type_str}:")
        for child in children:
            print_variable(child, child_prefix, child_prefix + "  ", depth + 1)
    else:
        print(f"{prefix}{name}{type_str}")
