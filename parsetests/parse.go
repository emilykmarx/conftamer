package parsetests

import (
	"encoding/csv"
	"os"

	"github.com/emilykmarx/conftamer/pkg/apimessages"
)

/* Functions for recording info during tests. */
type ParamKeys []string

type APIMessageInfo struct {
	controlFlow map[string]ParamKeys // receiver => param keys it accesses
}

// Info for each msg gathered across all tests (API call ID => influence)
type AllTaint map[apimessages.APICallID]APIMessageInfo

func (m *AllTaint) Dump(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	w := csv.NewWriter(file)
	defer w.Flush()

	rows :=
		[][]string{{
			"API", "Verb", "Resource", "CType", "Param key",
		}}

	for api_call_ID, msg_info := range *m {
		for recvr_type, keys := range msg_info.controlFlow {
			// Row for each recvr that sends this msg
			row := []string{api_call_ID.API, api_call_ID.Verb, api_call_ID.Resource}
			row = append(row, recvr_type)
			row = append(row, keys...)
			rows = append(rows, row)
		}
	}

	return w.WriteAll(rows)
}

func (m *AllTaint) AddCTypeMethodCall(api_call_id apimessages.APICallID, param_keys []string, recvr_type string) {
	// Can't edit map value in place => get it (initializing its maps if needed) and put it back

	existing_flow := (*m)[api_call_id]
	if existing_flow.controlFlow == nil {
		existing_flow.controlFlow = make(map[string]ParamKeys)
	}
	existing_flow.controlFlow[recvr_type] = param_keys

	(*m)[api_call_id] = existing_flow
}
