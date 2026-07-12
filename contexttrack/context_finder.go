// Context tracking and HTTP breakpoint management.
package contexttrack

import (
	"fmt"
	"strings"

	"github.com/go-delve/delve/service/api"
)

// HTTPBreakpointIDs holds the Delve breakpoint ID sets for each HTTP hook point.
type HTTPBreakpointIDs struct {
	ReqReceiveBpIDs           map[int]bool
	ReqReceiveH2BpIDs         map[int]bool
	ReqReceiveCaddyBpIDs      map[int]bool
	ReqReceiveCaddyRouteBpIDs map[int]bool
	ReqReceivePromHTTPBpIDs   map[int]bool
	ReqSendBpIDs              map[int]bool
	RespSendBpIDs             map[int]bool
	RespSendH2BpIDs           map[int]bool
	RespSendCaddyBpIDs        map[int]bool
	RespSendRecorderBpIDs     map[int]bool
	RespSendPromHTTPBpIDs     map[int]bool
	RespRecvBpIDs             map[int]bool
}

func SetHTTPBreakpoints(client *DelveClient) HTTPBreakpointIDs {
	// For HTTP/2, try both the external x/net/http2 package (Go <= 1.26) and
	// the bundled h2_bundle.go version (Go >= 1.27). SetBreakpointsFor prints a
	// WARNING and returns nil if a function is not found, so whichever copy is
	// absent in this binary is silently skipped.
	return HTTPBreakpointIDs{
		ReqReceiveBpIDs: SetBreakpointsFor(client, Breakpoints["HTTPReceiveFunc"]),
		ReqReceiveH2BpIDs: mergeSets(
			SetBreakpointsFor(client, Breakpoints["HTTPReceiveFuncH2"]),
			SetBreakpointsFor(client, Breakpoints["HTTPReceiveFuncH2Bundled"]),
		),
		ReqReceiveCaddyBpIDs:      SetBreakpointsFor(client, Breakpoints["HTTPReceiveFuncCaddy"]),
		ReqReceiveCaddyRouteBpIDs: SetBreakpointsFor(client, Breakpoints["HTTPReceiveFuncCaddyRoute"]),
		ReqReceivePromHTTPBpIDs:   SetBreakpointsFor(client, Breakpoints["HTTPReceiveFuncPromHTTP"]),
		ReqSendBpIDs:              SetBreakpointsFor(client, Breakpoints["HTTPSendFunc"]),
		RespSendBpIDs:             SetBreakpointsFor(client, Breakpoints["HTTPResponseFunc"]),
		RespSendH2BpIDs: mergeSets(
			SetBreakpointsFor(client, Breakpoints["HTTPResponseFuncH2"]),
			SetBreakpointsFor(client, Breakpoints["HTTPResponseFuncH2Bundled"]),
		),
		RespSendCaddyBpIDs:    SetBreakpointsFor(client, Breakpoints["HTTPResponseFuncCaddy"]),
		RespSendRecorderBpIDs: SetBreakpointsFor(client, Breakpoints["HTTPResponseFuncRecorder"]),
		RespSendPromHTTPBpIDs: SetBreakpointsFor(client, Breakpoints["HTTPResponseFuncPromHTTPReturn"]),
		RespRecvBpIDs:         SetBreakpointsFor(client, Breakpoints["HTTPRecvResponseFunc"]),
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

// walkContextChain walks the context parent chain starting from an already-eval'd
// variable, returning the root address as a hex string.
// Capped at 5 levels — real HTTP context chains are typically 2–4 deep.
func walkContextChain(client *DelveClient, goroutineID, frameID int, expr string, v *api.Variable, indent string) string {
	cur := expr
	curAddr := v.Addr
	for range 15 {
		found := false
		for _, getParent := range parentPointers {
			pe := getParent(cur)
			pv, err := client.EvalVariable(goroutineID, frameID, pe)
			if err == nil {
				cur = pe
				curAddr = pv.Addr
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	addrStr := "?"
	if curAddr != 0 {
		addrStr = fmt.Sprintf("0x%x", curAddr)
	}
	vprintf("%sroot context @ %s\n", indent, addrStr)
	return addrStr
}

// scanFrameVars returns all variables for a frame using the minimal ScanCfg.
func scanFrameVars(client *DelveClient, goroutineID, frame int) []api.Variable {
	var result []api.Variable
	if args, err := client.ScanFunctionArgs(goroutineID, frame); err == nil {
		result = append(result, args...)
	}
	if vars, err := client.ScanLocalVars(goroutineID, frame); err == nil {
		result = append(result, vars...)
	}
	return result
}

// findContextInFrame searches one stack frame for a context.Context.
// Uses ScanCfg to cheaply list variable types, then fetches full details only
// once the context variable is identified.
func findContextInFrame(client *DelveClient, goroutineID, frameID int, funcName string) *ContextInfo {
	allVars := scanFrameVars(client, goroutineID, frameID)

	// Strategy 1: explicit context.Context variable — re-fetch with full LoadCfg for printing.
	for i := range allVars {
		v := &allVars[i]
		if ContextTypes[v.Type] || ContextTypes[strings.TrimPrefix(v.Type, "*")] {
			full, err := client.EvalVariable(goroutineID, frameID, v.Name)
			if err != nil {
				full = v
			}
			vprintf("Context variable found: %s  (%s)\n", full.Name, full.Type)
			PrintVariable(full, "  ", "    ", 0)
			rootAddr := walkContextChain(client, goroutineID, frameID, v.Name, full, "   ")
			return &ContextInfo{Source: v.Name, Type: v.Type, RootAddr: rootAddr}
		}
	}

	// Strategies 2–4: find context through a known container type.
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
			vprintln("│")
			vprintf("└─ Context from %s in frame %d: %s\n", expr, frameID, funcName)
			vprintf("   type: %s\n", ctxV.Type)
			rootAddr := walkContextChain(client, goroutineID, frameID, expr, ctxV, "   ")
			return &ContextInfo{Source: expr, Type: ctxV.Type, RootAddr: rootAddr}
		}
	}

	return nil
}

// FindContext searches the goroutine's stack for a context.Context by walking up
// to StackDepth frames. It prints the backtrace and returns the context info found.
// It first tries a shallow stacktrace (ShallowStackDepth frames) and only fetches
// the full stack if the context is not found in the top frames.
//
// Strategies (tried per frame, in order):
//  1. Explicit context.Context variable
//  2. Context from *http.Request.ctx
//  3. Context from *http.response.req.ctx  (server-side)
//  4. Context from http.requestAndChan.treq.Request.ctx  (client-side)
//  5. Context from HTTP/2 response writer (bundled and external)
func FindContext(client *DelveClient, goroutineID int) *ContextInfo {
	vprintln("\n┌─ Stack backtrace (searching for context.Context) ────────────")

	frames, err := client.Stacktrace(goroutineID, ShallowStackDepth)
	if err != nil {
		vprintf("│  stacktrace error: %v\n", err)
		vprintln("└──────────────────────────────────────────────────────────────")
		return nil
	}

	ctx, framesVisited := searchFrames(client, goroutineID, frames, 0)
	if ctx != nil {
		vprintln("└──────────────────────────────────────────────────────────────")
		ctx.FramesSearched = framesVisited
		return ctx
	}

	// Not found in shallow pass — fetch the full stack and continue from where we left off.
	if len(frames) == ShallowStackDepth {
		deepFrames, err := client.Stacktrace(goroutineID, StackDepth)
		if err == nil && len(deepFrames) > len(frames) {
			ctx, moreVisited := searchFrames(client, goroutineID, deepFrames[len(frames):], len(frames))
			framesVisited = append(framesVisited, moreVisited...)
			if ctx != nil {
				vprintln("└──────────────────────────────────────────────────────────────")
				ctx.FramesSearched = framesVisited
				return ctx
			}
		}
	}

	vprintln("└──────────────────────────────────────────────────────────────")
	return &ContextInfo{FramesSearched: framesVisited}
}

func searchFrames(client *DelveClient, goroutineID int, frames []api.Stackframe, offset int) (*ContextInfo, []FrameInfo) {
	var visited []FrameInfo
	for i, frame := range frames {
		funcName := "<unknown>"
		if frame.Function != nil {
			funcName = frame.Function.Name()
		}
		idx := offset + i
		vprintf("│  [%2d] %s\n", idx, funcName)
		vprintf("│       %s:%d\n", frame.File, frame.Line)
		visited = append(visited, FrameInfo{Index: idx, Func: funcName, File: frame.File, Line: frame.Line})
		if ctx := findContextInFrame(client, goroutineID, idx, funcName); ctx != nil {
			return ctx, visited
		}
	}
	return nil, visited
}
