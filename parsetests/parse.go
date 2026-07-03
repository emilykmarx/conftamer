package parsetests

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"strings"

	"github.com/emilykmarx/conftamer/pkg/apimessages"
)

/* Functions for recording info during tests. */
type ParamKeys []string

type ParamHierarchy map[string]interface{}

type APIMessageInfo struct {
	controlFlow map[string]ParamKeys // receiver => param keys it accesses
}

// Info for each msg gathered across all tests (API call ID => influence)
type AllTaint map[apimessages.APICallID]APIMessageInfo

func InsertToParamHierarchy(m ParamHierarchy, parts []string) {
	// Keep indexing until prefix doesn't match, then insert the rest of the prefix
	if len(parts) == 0 {
		return
	}
	part := parts[0]
	if len(parts) == 1 {
		if _, ok := m[part]; ok {
			// Already inserted full key
		} else {
			// Insert last part
			m[part] = make(map[string]interface{})
		}
		return
	}

	if v_map, ok := m[part]; ok {
		// insert to existing map
		InsertToParamHierarchy(v_map.(map[string]interface{}), parts[1:])
	} else {
		// add map for rest of parts
		m[part] = make(map[string]interface{})
		InsertToParamHierarchy(m[part].(map[string]interface{}), parts[1:])
	}
}

// PARAM-FOCUSED FORMAT:
// Write the param keys in hierarchical format
// (should resemble the module's config file)
func (m *AllTaint) DumpHierarchy(filename string) error {
	// Arrange all observed params into hierarchy
	param_hierarchy := make(ParamHierarchy)

	for _, msg_info := range *m {
		for _, keys := range msg_info.controlFlow {
			for _, key := range keys {
				InsertToParamHierarchy(param_hierarchy, strings.Split(key, "."))
			}
		}
	}

	b, err := json.MarshalIndent(param_hierarchy, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, b, 0666)
}

// MESSAGE-FOCUSED FORMAT:
// A row per {msg type, CType} containing all param keys
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

	err = w.WriteAll(rows)
	if err != nil {
		return err
	}

	return m.DumpHierarchy("hierarchy_" + filename)
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
