package ctypes

import (
	"encoding/csv"
	"encoding/json"
	"log"
	"os"

	"github.com/emilykmarx/conftamer/runtimeinfo"
)

/* Functions and interfaces modules should use to log CType methods/params. */

const (
	MethodEntryLog = "ENTER CTYPES METHOD"
	MethodExitLog  = "EXIT CTYPES METHOD"
)

// The key and value of a config param that a CType has access to,
// via copy or alias.
// TODO (CTypes tool): also for fields set "because of" a param).
type CTypeParam struct {
	Key   string
	Value string
}

// Modules should implement this for each of their CTypes.
type CType interface {
	// Return all the params that this CType has access to.
	// TODO (CTypes tool): If param is set to an "uninteresting" value, skip it
	// (presume the test isn't meant to exercise it) - for DF this is taken care of bc JSON marshal omits message fields with `omitempty`,
	// but still needed for CF
	CTypeParams() []CTypeParam
}

// Modules should call this on entry to each of their CTypes methods (on the calling goroutine).
// Log method name and params.
func LogCTypesMethodEntry(ctype CType) {
	w := csv.NewWriter(os.Stdout)

	params, err := json.Marshal(ctype.CTypeParams())
	if err != nil {
		log.Panicf("marshaling %v: %v\n", ctype.CTypeParams(), err.Error())
	}
	w.WriteAll([][]string{
		{MethodEntryLog, runtimeinfo.Goid(), runtimeinfo.GetCaller().Func.Name(),
			string(params)},
	})
}

// Modules should call this on exit from each of their CTypes methods (on the calling goroutine).
func LogCTypesMethodExit() {
	w := csv.NewWriter(os.Stdout)
	w.WriteAll([][]string{
		{MethodExitLog, runtimeinfo.Goid(), runtimeinfo.GetCaller().Func.Name()},
	})
}
