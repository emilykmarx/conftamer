package parsetests

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
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

func InsertToParamHierarchy(m ParamHierarchy, parts []string, api_call_id string, recvr_type string,
	full_key string) { // just for logging

	if len(parts) == 0 {
		return
	}
	part := parts[0]
	if key_info, ok := m[part]; ok {
		if _, ok := key_info.(string); ok {
			if len(parts) != 1 {
				// e.g. already inserted a, found a.b => overwrite a
				fmt.Printf("Found full key %v but recorded prefix ending in %v as influencing %v - overwriting prefix influence\n", full_key, part, key_info)
				m[part] = make(map[string]interface{})
				InsertToParamHierarchy(m[part].(map[string]interface{}), parts[1:], api_call_id, recvr_type, full_key)
			} else {
				// Already inserted full key => add this {msg, recvr} pair
				m[part] = fmt.Sprintf("%v,%v,%v", key_info.(string), api_call_id, recvr_type)
			}
		} else {
			if len(parts) == 1 {
				// e.g. already inserted a.b, found a => skip a
				fmt.Printf("Found full key %v but postfix %v exists - skipping full key\n", full_key, key_info)
			} else {
				// Insert to existing map
				InsertToParamHierarchy(key_info.(map[string]interface{}), parts[1:], api_call_id, recvr_type, full_key)
			}
		}
	} else {
		if len(parts) == 1 {
			// Last part => insert key
			m[part] = fmt.Sprintf("%v,%v", api_call_id, recvr_type)
		} else {
			// Add map for rest of parts
			m[part] = make(map[string]interface{})
			InsertToParamHierarchy(m[part].(map[string]interface{}), parts[1:], api_call_id, recvr_type, full_key)
		}
	}
}

// PARAM-FOCUSED FORMAT:
// Write the param keys in hierarchical format
// (should resemble the module's config file)
func (m *AllTaint) DumpHierarchy(filename string) error {
	// Arrange all observed params into hierarchy
	param_hierarchy := make(ParamHierarchy)

	for api_call_id, msg_info := range *m {
		for recvr_type, keys := range msg_info.controlFlow {
			for _, key := range keys {
				api_call_str := fmt.Sprintf("%v:%v/%v", api_call_id.API, api_call_id.Verb, api_call_id.Resource)
				InsertToParamHierarchy(param_hierarchy, strings.Split(key, "."), api_call_str, recvr_type, key)
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

	for api_call_id, msg_info := range *m {
		for recvr_type, keys := range msg_info.controlFlow {
			// Row for each recvr that sends this msg
			row := []string{api_call_id.API, api_call_id.Verb, api_call_id.Resource}
			row = append(row, recvr_type)
			row = append(row, keys...)
			rows = append(rows, row)
		}
	}

	err = w.WriteAll(rows)
	if err != nil {
		return err
	}

	return m.DumpHierarchy(filename + "_hierarchy")
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
