package runtimeinfo

import (
	"bytes"
	"fmt"
	"log"
	"runtime"
	"strconv"
)

/* Info on runtime happenings (likely to be replaced by dlv eventually) */

// Info on caller of function that called this one (on current goroutine)
func GetCaller() runtime.Frame {
	pc := make([]uintptr, 15)
	n := runtime.Callers(3, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	return frame
}

// Return current goroutine ID (as string) - panic if can't
func Goid() string {
	goroutinePrefix := []byte("goroutine ")
	buf := make([]byte, 32)
	n := runtime.Stack(buf, false)
	buf = buf[:n]
	// goroutine 1 [running]: ...

	buf, ok := bytes.CutPrefix(buf, goroutinePrefix)
	if !ok {
		log.Panicf("goid\n")
	}

	i := bytes.IndexByte(buf, ' ')
	if i < 0 {
		log.Panicf("goid\n")
	}

	goid, err := strconv.Atoi(string(buf[:i]))
	if err != nil {
		log.Panicf("goid\n")
	}
	return fmt.Sprintf("%v", goid)
}
