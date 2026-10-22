#!/bin/sh
# x-net-http2-server.sh DIR: instrument golang.org/x/net/http2's server, in the
# x/net module at DIR, like the patched net/http's bundled copy (h2_bundle.go):
#   - each request gets a context ID and its connection (with its stream)
#   - "Request received", unless net/http's top-level handler logs it
#   - "Response sent"
# A script rather than a .patch: components link many x/net versions, and the
# code around these points differs between them. Needs the conftamer-patched Go
# (the hooks are http.Conftamer* in its net/http). Idempotent.
set -eu

f=$1/http2/server.go
[ -f "$f" ] || { echo "x-net-http2-server.sh: no $f" >&2; exit 1; }
grep -q ConftamerServerRequest "$f" && exit 0

awk '
/^func \(sc \*serverConn\) newWriterAndRequestNoBody\(/ { body = 1 }
body && /^}/ { body = 0 }
{ print }
# The request is complete: "req = req.WithContext(st.ctx)" (older) or
# "}).WithContext(st.ctx)" (newer, after httpcommon.NewServerRequest).
body && /^\t(req = req|\}\))\.WithContext\(st\.ctx\)$/ {
    print "\treq = http.ConftamerServerRequest(req, sc.conn, st.id)"; n++
}
/^func \(sc \*serverConn\) runHandler\(rw \*responseWriter, req \*http\.Request, / {
    print "\thttp.ConftamerLogRequestReceived(req, sc.handler)"; n++
}
/^func \(w \*responseWriter\) WriteHeader\(code int\) \{$/ {
    print "\tif w.rws != nil && !w.rws.wroteHeader {"
    print "\t\thttp.ConftamerLogResponseSent(w.rws.req, code)"
    print "\t}"
    n++
}
END { if (n != 3) { print "x-net-http2-server.sh: matched " n " of 3 points" > "/dev/stderr"; exit 1 } }
' "$f" > "$f.conftamer"
mv "$f.conftamer" "$f"
