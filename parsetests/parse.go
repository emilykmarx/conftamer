package parsetests

import (
	"github.com/emilykmarx/conftamer/pkg/apimessages"
	"github.com/emilykmarx/conftamer/pkg/ctypes"
)

/* Functions for recording info during tests. */

// A CType method and corresponding params
type MethodParams struct {
	method string
	params []ctypes.CTypeParam
}
type APIMessageInfo struct {
	controlFlow map[string]map[string]struct{} // param key => methods that found CF from param to msg
}

// Info for each msg gathered across all tests (API call ID => influence)
type AllTaint map[apimessages.APICallID]APIMessageInfo

func (m *AllTaint) AddCTypeMethodCall(api_call_id apimessages.APICallID, param_keys []string, method string) {
	// Can't edit map value in place => get it (initializing its maps if needed) and put it back

	// XXX write to csv (split out msg ID parts)
	existing_flow := (*m)[api_call_id]
	if existing_flow.controlFlow == nil {
		existing_flow.controlFlow = make(map[string]map[string]struct{})
	}

	for _, param_key := range param_keys {
		existing_methods := existing_flow.controlFlow[param_key]
		if existing_methods == nil {
			existing_methods = make(map[string]struct{})
		}
		existing_methods[method] = struct{}{}
		existing_flow.controlFlow[param_key] = existing_methods
	}

	(*m)[api_call_id] = existing_flow
}
