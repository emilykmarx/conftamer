// Context tracking and HTTP breakpoint management.
package contexttrack

import (
	"fmt"
	"strings"
)

// HTTPBreakpointIDs holds the Delve breakpoint ID sets for each HTTP hook point.
type HTTPBreakpointIDs struct {
	ReqReceiveBpIDs   map[int]bool
	ReqReceiveH2BpIDs map[int]bool
	ReqSendBpIDs      map[int]bool
	RespSendBpIDs     map[int]bool
	RespSendH2BpIDs   map[int]bool
	RespRecvBpIDs     map[int]bool
}

func SetHTTPBreakpoints(client *DelveClient) HTTPBreakpointIDs {
	// For HTTP/2, try both the external x/net/http2 package (Go <= 1.26) and
	// the bundled h2_bundle.go version (Go >= 1.27). SetBreakpointsFor prints a
	// WARNING and returns nil if a function is not found, so whichever copy is
	// absent in this binary is silently skipped.
	return HTTPBreakpointIDs{
		ReqReceiveBpIDs: SetBreakpointsFor(client, HTTPReceiveFunc, "req-received"),
		ReqReceiveH2BpIDs: mergeSets(
			SetBreakpointsFor(client, HTTPReceiveFuncH2, "req-received-h2"),
			SetBreakpointsFor(client, HTTPReceiveFuncH2Bundled, "req-received-h2-bundled"),
		),
		ReqSendBpIDs:  SetBreakpointsFor(client, HTTPSendFunc, "req-sent"),
		RespSendBpIDs: SetBreakpointsFor(client, HTTPResponseFunc, "resp-sent"),
		RespSendH2BpIDs: mergeSets(
			SetBreakpointsFor(client, HTTPResponseFuncH2, "resp-sent-h2"),
			SetBreakpointsFor(client, HTTPResponseFuncH2Bundled, "resp-sent-h2-bundled"),
		),
		RespRecvBpIDs: SetBreakpointsFor(client, HTTPRecvResponseFunc, "resp-received"),
	}
}

func mergeSets(a, b map[int]bool) map[int]bool {
	result := make(map[int]bool)
	for k := range a {
		result[k] = true
	}
	for k := range b {
		result[k] = true
	}
	return result
}

// parentPointers are expressions that follow one level of context parent pointer.
var parentPointers = []func(string) string{
	func(cur string) string { return fmt.Sprintf("(%s).(*context.valueCtx).Context", cur) },
	func(cur string) string { return fmt.Sprintf("(%s).(*context.cancelCtx).Context", cur) },
	func(cur string) string { return fmt.Sprintf("(%s).(*context.timerCtx).cancelCtx.Context", cur) },
}

type ctxContainer struct {
	types    map[string]bool
	makeExpr func(name string) string
}

// ctxContainers maps container types to the expression that extracts their embedded context.
var ctxContainers = []ctxContainer{
	{
		types:    map[string]bool{"*net/http.Request": true, "net/http.Request": true},
		makeExpr: func(n string) string { return n + ".ctx" },
	},
	{
		types:    map[string]bool{"*net/http.response": true, "net/http.response": true},
		makeExpr: func(n string) string { return n + ".req.ctx" },
	},
	{
		types:    map[string]bool{"*net/http.requestAndChan": true, "net/http.requestAndChan": true},
		makeExpr: func(n string) string { return n + ".treq.Request.ctx" },
	},
	// HTTP/2 response writer (bundled h2_bundle.go, Go >= 1.27)
	{
		types:    map[string]bool{"*net/http.http2responseWriter": true, "net/http.http2responseWriter": true},
		makeExpr: func(n string) string { return n + ".rws.req.ctx" },
	},
	// HTTP/2 response writer (external x/net/http2, Go <= 1.26)
	{
		types:    map[string]bool{"*golang.org/x/net/http2.responseWriter": true, "golang.org/x/net/http2.responseWriter": true},
		makeExpr: func(n string) string { return n + ".rws.req.ctx" },
	},
}

// FrameInfo is one entry in the backtrace recorded when searching for a context.
type FrameInfo struct {
	Index int    `json:"index"`
	Func  string `json:"func"`
	File  string `json:"file"`
	Line  int    `json:"line"`
}

// ContextInfo is the result of FindContext.
type ContextInfo struct {
	Source         string      `json:"source,omitempty"`
	Type           string      `json:"type,omitempty"`
	RootAddr       string      `json:"root_addr,omitempty"`
	FramesSearched []FrameInfo `json:"frames_searched,omitempty"`
	Error          string      `json:"error,omitempty"`
}

// walkContextChain walks the context parent chain, prints each step, and returns
// the root address as a hex string.
func walkContextChain(client *DelveClient, goroutineID, frameID int, expr, indent string) string {
	cur := expr
	for range 20 {
		moved := false
		for _, getParent := range parentPointers {
			nextExpr := getParent(cur)
			if _, err := client.EvalVariable(goroutineID, frameID, nextExpr); err == nil {
				cur = nextExpr
				moved = true
				break
			}
		}
		if !moved {
			v, err := client.EvalVariable(goroutineID, frameID, cur)
			if err != nil {
				return "?"
			}
			addrStr := "?"
			if v.Addr != 0 {
				addrStr = fmt.Sprintf("0x%x", v.Addr)
			}
			fmt.Printf("%sroot context @ %s\n", indent, addrStr)
			return addrStr
		}
	}
	return "?"
}

// findContextInFrame searches one stack frame for a context.Context.
func findContextInFrame(client *DelveClient, goroutineID, frameID int, funcName string) *ContextInfo {
	allVars := GetAllFrameVars(client, goroutineID, frameID)

	// Strategy 1: explicit context.Context variable
	for i := range allVars {
		v := &allVars[i]
		if ContextTypes[v.Type] || ContextTypes[strings.TrimPrefix(v.Type, "*")] {
			fmt.Printf("Context variable found: %s  (%s)\n", v.Name, v.Type)
			PrintVariable(v, "  ", "    ", 0)
			rootAddr := walkContextChain(client, goroutineID, frameID, v.Name, "   ")
			return &ContextInfo{Source: v.Name, Type: v.Type, RootAddr: rootAddr}
		}
	}

	// Strategies 2–4: find context through a known container type
	for _, container := range ctxContainers {
		for i := range allVars {
			v := &allVars[i]
			if !container.types[v.Type] {
				continue
			}
			expr := container.makeExpr(v.Name)
			ctxV, err := client.EvalVariable(goroutineID, frameID, expr)
			if err != nil || ctxV.Type == "" {
				continue
			}
			fmt.Println("│")
			fmt.Printf("└─ Context from %s in frame %d: %s\n", expr, frameID, funcName)
			fmt.Printf("   type: %s\n", ctxV.Type)
			rootAddr := walkContextChain(client, goroutineID, frameID, expr, "   ")
			return &ContextInfo{Source: expr, Type: ctxV.Type, RootAddr: rootAddr}
		}
	}

	return nil
}

// FindContext searches the goroutine's stack for a context.Context by walking up
// to StackDepth frames. It prints the backtrace and returns the context info found.
//
// Strategies (tried per frame, in order):
//  1. Explicit context.Context variable
//  2. Context from *http.Request.ctx
//  3. Context from *http.response.req.ctx  (server-side)
//  4. Context from http.requestAndChan.treq.Request.ctx  (client-side)
//  5. Context from HTTP/2 response writer (bundled and external)
func FindContext(client *DelveClient, goroutineID int) *ContextInfo {
	fmt.Println("\n┌─ Stack backtrace (searching for context.Context) ────────────")

	frames, err := client.Stacktrace(goroutineID)
	if err != nil {
		fmt.Printf("│  stacktrace error: %v\n", err)
		fmt.Println("└──────────────────────────────────────────────────────────────")
		return nil
	}

	var framesVisited []FrameInfo
	for i, frame := range frames {
		funcName := "<unknown>"
		if frame.Function != nil {
			funcName = frame.Function.Name()
		}
		fmt.Printf("│  [%2d] %s\n", i, funcName)
		fmt.Printf("│       %s:%d\n", frame.File, frame.Line)
		framesVisited = append(framesVisited, FrameInfo{
			Index: i, Func: funcName, File: frame.File, Line: frame.Line,
		})
		if ctx := findContextInFrame(client, goroutineID, i, funcName); ctx != nil {
			fmt.Println("└──────────────────────────────────────────────────────────────")
			ctx.FramesSearched = framesVisited
			return ctx
		}
	}

	fmt.Println("└──────────────────────────────────────────────────────────────")
	return &ContextInfo{FramesSearched: framesVisited}
}
