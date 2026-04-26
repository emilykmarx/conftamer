package conftamer

import (
	"bytes"
	"fmt"
	"log"
	"runtime"
	"strconv"
)

// Flatten to k,v pairs of strings - e.g. map[grandparent:map[parent:map[key:value]]] => [grandparent.parent.key:value]
func unnest(m map[string]interface{}, fields *[]MsgField, key_prefix string, exclude map[string]struct{}) {
	for k, v := range m {
		if _, ok := exclude[k]; ok {
			continue
		}
		key := key_prefix + "." + k
		if key_prefix == "" {
			key = k
		}
		if v_map, ok := v.(map[string]interface{}); ok {
			unnest(v_map, fields, key, exclude)
		} else {
			v_str := fmt.Sprintf("%v", v)
			(*fields) = append(*fields, MsgField{Key: key, Value: v_str})
		}
	}
}

// Info on caller of function that called this one (on current goroutine)
func GetCaller() runtime.Frame {
	pc := make([]uintptr, 15)
	n := runtime.Callers(3, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	return frame
}

// Return current goroutine ID (as string) - panic if can't
func goid() string {
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
