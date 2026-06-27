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
	fmt.Printf("\n┌─ %s\n", header)
	data := make(map[string]string, len(exprs))
	for _, expr := range exprs {
		resolvedExpr, val := evalWithFallbacks(client, goroutineID, expr)
		data[resolvedExpr] = val
		fmt.Printf("│  %-26s = %s\n", resolvedExpr, val)
	}
	fmt.Println("└──────────────────────────────────────────────────────────────")
	return data
}

func GetHTTPRequestRecvd(client *DelveClient, goroutineID int) map[string]string {
	return printAndCollect(client, goroutineID,
		"HTTP Request (received by server) ─────────────────────────",
		[]string{"r.Method", "r.URL.Path", "r.URL.RawQuery", "r.Header", "r.RemoteAddr", "r.Proto"})
}

func GetHTTPRequestSent(client *DelveClient, goroutineID int) map[string]string {
	return printAndCollect(client, goroutineID,
		"HTTP Request (message being sent) ─────────────────────────",
		[]string{"req.Method", "req.URL.Scheme", "req.URL.Host", "req.URL.Path", "req.URL.RawQuery", "req.Header"})
}

func GetHTTPResponseSent(client *DelveClient, goroutineID int) map[string]string {
	return printAndCollect(client, goroutineID,
		"HTTP Response (message being sent, HTTP/1.x) ──────────────",
		[]string{"code", "w.handlerHeader", "w.req.Method", "w.req.URL.Path", "w.req.URL.RawQuery"})
}

func GetHTTPResponseSentH2(client *DelveClient, goroutineID int) map[string]string {
	return printAndCollect(client, goroutineID,
		"HTTP Response (message being sent, HTTP/2) ────────────────",
		[]string{"code", "w.rws.handlerHeader", "w.rws.req.Method", "w.rws.req.URL.Path", "w.rws.req.URL.RawQuery"})
}

func GetHTTPResponseRecvd(client *DelveClient, goroutineID int) map[string]string {
	fmt.Println("\n┌─ HTTP Response (received) ───────────────────────────────────")
	allVars := GetAllFrameVars(client, goroutineID, 0)

	var respVarName string
	for _, v := range allVars {
		if v.Type == "*net/http.Response" || v.Type == "net/http.Response" {
			respVarName = v.Name
			break
		}
	}
	if respVarName == "" {
		fmt.Println("│  (no *http.Response variable found in frame 0)")
		fmt.Println("└──────────────────────────────────────────────────────────────")
		return map[string]string{}
	}

	data := make(map[string]string)
	for _, field := range []string{"Status", "StatusCode", "Proto", "Header"} {
		val := evalFlat(client, goroutineID, 0, respVarName+"."+field)
		key := "resp." + field
		data[key] = val
		fmt.Printf("│  resp.%-21s = %s\n", field, val)
	}
	for _, field := range []string{"Method", "URL.Host", "URL.Path", "URL.RawQuery"} {
		val := evalFlat(client, goroutineID, 0, "ireq."+field)
		key := "ireq." + field
		data[key] = val
		fmt.Printf("│  ireq.%-21s = %s\n", field, val)
	}
	fmt.Println("└──────────────────────────────────────────────────────────────")
	return data
}
