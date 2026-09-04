package parsetests

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/emilykmarx/conftamer/pkg/apimessages"
	"go.yaml.in/yaml/v3"
)

/* Functions for recording info during tests. */
type ParamKeys []string

type APIMessageInfo struct {
	controlFlow map[string]ParamKeys // receiver => param keys it accesses
}

// Info for each msg gathered across all tests (API call ID => influence)
type AllTaint map[apimessages.APICallID]APIMessageInfo

const FAKE_API = "FAKE_API" // for param dumping

type ParamHierarchy map[string]HierarchyValue
type HierarchyValue struct {
	// Msgs influenced by key paths ending with this one
	Msgs string `yaml:",omitempty"`
	// paths to postfixes
	Fields map[string]HierarchyValue `yaml:",inline"`
}

func InsertToParamHierarchy(m ParamHierarchy, parts []string, api_call_id apimessages.APICallID) {
	if len(parts) == 0 {
		return
	}
	part := parts[0]
	if key_info, ok := m[part]; ok {
		if len(parts) == 1 {
			// Already inserted full key => add this {msg, recvr} pair
			if !strings.Contains(key_info.Msgs, api_call_id.String()) {
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
			if api_call_id.API != FAKE_API {
				val.Msgs = api_call_id.String()
			}
			m[part] = val
		} else {
			// More parts => insert them
			m[part] = val
			InsertToParamHierarchy(m[part].Fields, parts[1:], api_call_id)
		}
	}
}

func (m ParamHierarchy) Marshal() []byte {
	b, err := yaml.Marshal(m)
	if err != nil {
		panic(err)
	}

	return b
}

// PARAM-FOCUSED FORMAT:
// Write the param keys in hierarchical format
// (should resemble the module's config file)
func (m *AllTaint) DumpHierarchy(path string) error {
	// Arrange all observed params into hierarchy
	param_hierarchy := make(ParamHierarchy)

	for api_call_id, msg_info := range *m {
		for _, keys := range msg_info.controlFlow {
			for _, key := range keys {
				InsertToParamHierarchy(param_hierarchy, strings.Split(key, "."), api_call_id)
			}
		}
	}

	b := param_hierarchy.Marshal()

	return os.WriteFile(filepath.Join(path, "params.yaml"), b, 0666)
}

// MESSAGE-FOCUSED FORMAT:
// A row per {msg type, CType} containing all param keys
func (m *AllTaint) Dump(path string) error {
	file, err := os.Create(filepath.Join(path, "msgs.csv"))
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
			// TODO(CT) we sometimes write e.g. alerting.alertmanagers as a complete key even though it's not a leaf -
			// only in the csv, but the yaml is correct
			// (e.g. for ingress /discovery.Config, but not for github.com/prometheus/common/config.Header)
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

	return m.DumpHierarchy(path)
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
