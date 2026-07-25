package parsetests

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/emilykmarx/conftamer/pkg/apimessages"
)

/* Functions for recording info during tests. */
type ParamKeys []string

type APIMessageInfo struct {
	controlFlow map[string]ParamKeys // receiver => param keys it accesses
}

// Info for each msg gathered across all tests (API call ID => influence)
type AllTaint map[apimessages.APICallID]APIMessageInfo

type ParamHierarchy map[string]HierarchyValue
type HierarchyValue struct {
	// Msgs influenced by key paths ending with this one
	Msgs string `json:",omitempty"`
	// paths to postfixes
	Fields map[string]HierarchyValue `json:" ,omitempty"`
}

func InsertToParamHierarchy(m ParamHierarchy, parts []string, api_call_id string) {
	if len(parts) == 0 {
		return
	}
	part := parts[0]
	if key_info, ok := m[part]; ok {
		if len(parts) == 1 {
			// Already inserted full key => add this {msg, recvr} pair
			if !strings.Contains(key_info.Msgs, api_call_id) {
				key_info.Msgs = fmt.Sprintf("%v %v", key_info.Msgs, api_call_id)
				m[part] = key_info
			}
		} else {
			// Insert rest of parts to existing map
			InsertToParamHierarchy(key_info.Fields, parts[1:], api_call_id)
		}
	} else {
		// Add part, with map for rest of parts
		val := HierarchyValue{
			Fields: make(map[string]HierarchyValue),
		}
		if len(parts) == 1 {
			// Last part => insert msg
			val.Msgs = api_call_id
			m[part] = val
		} else {
			// More parts => insert them
			m[part] = val
			InsertToParamHierarchy(m[part].Fields, parts[1:], api_call_id)
		}
	}
}

func (m ParamHierarchy) Marshal() []byte {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		panic(err)
	}
	pretty := strings.ReplaceAll(string(b), "\"", "")
	pretty = strings.ReplaceAll(pretty, "{", "")
	pretty = strings.ReplaceAll(pretty, "}", "")
	pretty = strings.ReplaceAll(pretty, ":", "")
	pretty = strings.ReplaceAll(pretty, ",", "")
	re := regexp.MustCompile("\n +\n")
	for {
		before_replace := pretty
		pretty = string(re.ReplaceAll([]byte(pretty), []byte("\n")))
		if pretty == before_replace {
			break
		}
	}
	re = regexp.MustCompile("\n +Msgs +")
	pretty = string(re.ReplaceAll([]byte(pretty), []byte("=> ")))
	return []byte(pretty)
}

// PARAM-FOCUSED FORMAT:
// Write the param keys in hierarchical format
// (should resemble the module's config file)
func (m *AllTaint) DumpHierarchy(filename string) error {
	// Arrange all observed params into hierarchy
	param_hierarchy := make(ParamHierarchy)

	for api_call_id, msg_info := range *m {
		for _, keys := range msg_info.controlFlow {
			for _, key := range keys {
				// assume resource already has a / prefix
				api_call_str := fmt.Sprintf("%v-%v%v", api_call_id.API, api_call_id.Verb, api_call_id.Resource)
				InsertToParamHierarchy(param_hierarchy, strings.Split(key, "."), api_call_str)
			}
		}
	}

	b := param_hierarchy.Marshal()

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

func CombineTaints(list []AllTaint) AllTaint {
	all := make(AllTaint)
	for _, one := range list {
		for api_call_id, msg_info := range one {
			for recvr_type, keys := range msg_info.controlFlow {
				all.AddCTypeMethodCall(api_call_id, keys, recvr_type)
			}
		}
	}
	return all
}
