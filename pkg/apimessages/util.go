package apimessages

import "fmt"

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
