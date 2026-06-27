// Printing and data-collection helpers for HTTP messages.
// Each function prints the message to the terminal and returns its fields as a map.
package contexttrack

import (
	"fmt"
	"strings"
)

func evalFlat(client *DelveClient, goroutineID, frame int, expr string) string {
	v, err := client.EvalVariable(goroutineID, frame, expr)
	if err != nil {
		return fmt.Sprintf("<error: %v>", err)
	}
	return FlatValue(v)
}

// evalWithFallbacks tries expr as-is; if it fails and starts with a known request
// variable name, retries with alternate names (r <-> req).
func evalWithFallbacks(client *DelveClient, goroutineID int, expr string) (string, string) {
	val := evalFlat(client, goroutineID, 0, expr)
	if !strings.HasPrefix(val, "<error:") {
		return expr, val
	}
	prefix, rest, found := strings.Cut(expr, ".")
	if !found {
		return expr, val
	}
	alternates := map[string][]string{
		"r":   {"req"},
		"req": {"r"},
	}
	for _, alt := range alternates[prefix] {
		altExpr := alt + "." + rest
		altVal := evalFlat(client, goroutineID, 0, altExpr)
		if !strings.HasPrefix(altVal, "<error:") {
			return altExpr, altVal
		}
	}
	return expr, val
}

func printAndCollect(client *DelveClient, goroutineID int, header string, exprs []string) map[string]string {
	vprintf("\n┌─ %s\n", header)
	data := make(map[string]string, len(exprs))
	for _, expr := range exprs {
		resolvedExpr, val := evalWithFallbacks(client, goroutineID, expr)
		data[resolvedExpr] = val
		vprintf("│  %-26s = %s\n", resolvedExpr, val)
	}
	vprintln("└──────────────────────────────────────────────────────────────")
	return data
}

func GetHTTPRequestRecvd(client *DelveClient, goroutineID int) map[string]string {
	return printAndCollect(client, goroutineID,
		"HTTP Request (received by server) ─────────────────────────",
		[]string{"r.Method", "r.URL.Path", "r.URL.RawQuery"})
}

func GetHTTPRequestSent(client *DelveClient, goroutineID int) map[string]string {
	return printAndCollect(client, goroutineID,
		"HTTP Request (message being sent) ─────────────────────────",
		[]string{"req.Method", "req.URL.Host", "req.URL.Path", "req.URL.RawQuery"})
}

func GetHTTPResponseSent(client *DelveClient, goroutineID int) map[string]string {
	return printAndCollect(client, goroutineID,
		"HTTP Response (message being sent, HTTP/1.x) ──────────────",
		[]string{"code", "w.req.Method", "w.req.URL.Path"})
}

func GetHTTPResponseSentH2(client *DelveClient, goroutineID int) map[string]string {
	return printAndCollect(client, goroutineID,
		"HTTP Response (message being sent, HTTP/2) ────────────────",
		[]string{"code", "w.rws.req.Method", "w.rws.req.URL.Path"})
}

func GetHTTPResponseRecvd(client *DelveClient, goroutineID int) map[string]string {
	vprintln("\n┌─ HTTP Response (received) ───────────────────────────────────")
	allVars := scanFrameVars(client, goroutineID, 0)

	var respVarName string
	for _, v := range allVars {
		if v.Type == "*net/http.Response" || v.Type == "net/http.Response" {
			respVarName = v.Name
			break
		}
	}
	if respVarName == "" {
		vprintln("│  (no *http.Response variable found in frame 0)")
		vprintln("└──────────────────────────────────────────────────────────────")
		return map[string]string{}
	}

	data := make(map[string]string)
	for _, field := range []string{"StatusCode", "Status"} {
		val := evalFlat(client, goroutineID, 0, respVarName+"."+field)
		key := "resp." + field
		data[key] = val
		vprintf("│  resp.%-21s = %s\n", field, val)
	}
	for _, field := range []string{"Method", "URL.Path"} {
		val := evalFlat(client, goroutineID, 0, "ireq."+field)
		key := "ireq." + field
		data[key] = val
		vprintf("│  ireq.%-21s = %s\n", field, val)
	}
	vprintln("└──────────────────────────────────────────────────────────────")
	return data
}
