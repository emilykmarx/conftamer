// Delve client that tracks context propagation to associate each received HTTP
// message with a subsequent sent HTTP message.
//
// Usage:
//
//	Terminal 1: start target under delve (disable inlining for net/http)
//	    dlv debug --headless --listen=:2345 --api-version=2 --build-flags="-gcflags=net/http=-l" .
//	    or:
//	        dlv test --headless --listen=:2345 --api-version=2 --build-flags="-gcflags=net/http=-l" [directory] [options]
//
//	Terminal 2: run this program
//	    go run ./contexttrack/client [--addr localhost:2345] [--output events.jsonl]
//
//	Terminal 3 (for the ContextBlog example): make a request to the target server
//	    curl "http://localhost:8080/search?q=golang"
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/emilykmarx/conftamer/contexttrack"
)

// event is the JSON record written to the output file for each HTTP breakpoint hit.
type event struct {
	Kind        string            `json:"kind"`
	GoroutineID int               `json:"goroutine_id"`
	ThreadID    int               `json:"thread_id"`
	File        string            `json:"file"`
	Line        int               `json:"line"`
	Message     map[string]string `json:"message"`
	Context     *contexttrack.ContextInfo `json:"context"`
}

type bpHandler struct {
	ids     map[int]bool
	kind    string
	handler func(*contexttrack.DelveClient, int) map[string]string
}

func findHandler(handlers []bpHandler, bpID int) (string, func(*contexttrack.DelveClient, int) map[string]string) {
	for _, h := range handlers {
		if h.ids[bpID] {
			return h.kind, h.handler
		}
	}
	return "Unknown", nil
}

func main() {
	addr := flag.String("addr", "localhost:2345", "Delve headless server address")
	output := flag.String("output", "", "JSON Lines file to append events to (one object per line)")
	verbose := flag.Bool("verbose", false, "print breakpoint and context details to the terminal")
	flag.Parse()

	contexttrack.Verbose = *verbose

	client := contexttrack.NewDelveClient(*addr)

	var outFile *os.File
	if *output != "" {
		f, err := os.OpenFile(*output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open output file: %v\n", err)
			os.Exit(1)
		}
		outFile = f
		defer outFile.Close()
	}

	if *verbose {
		fmt.Println("Setting breakpoints:")
	}
	bpIDs := contexttrack.SetHTTPBreakpoints(client)
	if *verbose {
		fmt.Println("Waiting for HTTP events… (Ctrl-C to stop)\n")
	}

	handlers := []bpHandler{
		{bpIDs.ReqReceiveBpIDs,      "Request received", contexttrack.GetHTTPRequestRecvd},
		{bpIDs.ReqReceiveH2BpIDs,    "Request received", contexttrack.GetHTTPRequestRecvd},
		{bpIDs.ReqReceiveCaddyBpIDs, "Request received", contexttrack.GetHTTPRequestRecvd},
		{bpIDs.ReqSendBpIDs,         "Request sent",     contexttrack.GetHTTPRequestSent},
		{bpIDs.RespSendBpIDs,        "Response sent",    contexttrack.GetHTTPResponseSent},
		{bpIDs.RespSendH2BpIDs,      "Response sent",    contexttrack.GetHTTPResponseSentH2},
		{bpIDs.RespRecvBpIDs,        "Response received", contexttrack.GetHTTPResponseRecvd},
	}

	for {
		state := client.Continue()
		if state == nil {
			fmt.Fprintln(os.Stderr, "Lost connection to Delve.")
			break
		}
		if state.Exited {
			fmt.Printf("\nProcess exited (status %d)\n", state.ExitStatus)
			break
		}
		if state.Err != nil {
			// "connection is shut down" is a race in delve's headless mode: the
			// process exits and delve closes the RPC before sending state.Exited.
			// Treat it as a clean exit rather than an error.
			if strings.Contains(state.Err.Error(), "connection is shut down") {
				fmt.Println("\nProcess exited (connection closed).")
			} else {
				fmt.Fprintf(os.Stderr, "Debugger error: %v\n", state.Err)
			}
			break
		}

		thread := state.CurrentThread
		if thread == nil {
			continue
		}
		goroutineID := int(thread.GoroutineID)
		bpID := 0
		if thread.Breakpoint != nil {
			bpID = thread.Breakpoint.ID
		}

		kind, handler := findHandler(handlers, bpID)

		if *verbose {
			fmt.Println("╔══════════════════════════════════════════════════════════════╗")
			fmt.Printf("║  HTTP %s — goroutine %d, thread %d\n", kind, goroutineID, thread.ID)
			fmt.Printf("║  %s:%d\n", thread.File, thread.Line)
			fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		}

		var msgData map[string]string
		if handler != nil {
			msgData = handler(client, goroutineID)
		}

		ctxData := contexttrack.FindContext(client, goroutineID)

		if outFile != nil {
			ev := event{
				Kind:        kind,
				GoroutineID: goroutineID,
				ThreadID:    thread.ID,
				File:        thread.File,
				Line:        thread.Line,
				Message:     msgData,
				Context:     ctxData,
			}
			line, _ := json.Marshal(ev)
			outFile.Write(append(line, '\n'))
		}

		if *verbose {
			fmt.Println()
		}
	}
}
