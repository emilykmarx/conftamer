package conftamer

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

/* Functions for parsing module test logs. */

// Data flow from param to msgField
type DataFlow struct {
	paramKey string
	msgField string
}

// Info about a method called in a test that found flow from a given param
type testMethod struct {
	test   string
	method string
	// Value of param in the test method (for convenience)
	paramValue string
}

// A CType method and corresponding params
type MethodParams struct {
	method string
	params []CTypeParam
}
type APIMessageInfo struct {
	controlFlow map[string][]testMethod   // param key => tests that found CF from param to msg
	dataFlow    map[DataFlow][]testMethod // {param key, msg field} => tests that found DF from param to msg field
}

// Taint info for each msg gathered across all tests (API call ID => influence)
type AllTaint map[APICallID]APIMessageInfo

// Eventually may want something more graphable
func (m *AllTaint) prettyPrint(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	w := bufio.NewWriter(file)
	defer w.Flush()

	api_call_string_template := "\n%s\n"
	method_string_template := "%s : %s (param set to %s)"
	cf_string_templates := []string{"\tCF\n", "\t\t%s\n", "\t\t\t" + method_string_template + "\n"}
	df_string_templates := []string{"\tDF\n", "\t\t%s\n", "\t\t\t%s\n", "\t\t\t\t" + method_string_template + "\n"}

	w.WriteString("***FORMAT***\n")
	w.WriteString(fmt.Sprintf(api_call_string_template, "API CALL"))
	w.WriteString(cf_string_templates[0])
	w.WriteString(fmt.Sprintf(cf_string_templates[1], "Param key"))
	w.WriteString(fmt.Sprintf(cf_string_templates[2], "Test", "method", "<param value>"))
	w.WriteString(df_string_templates[0])
	w.WriteString(fmt.Sprintf(df_string_templates[1], "Msg field key"))
	w.WriteString(fmt.Sprintf(df_string_templates[2], "Param key"))
	w.WriteString(fmt.Sprintf(df_string_templates[3], "Test", "method", "<param value>"))

	w.WriteString("\n\n***OUTPUT***\n")

	for api_call_id, info := range *m {
		w.WriteString(fmt.Sprintf(api_call_string_template, api_call_id))

		w.WriteString(cf_string_templates[0])
		for param_key, test_methods := range info.controlFlow {
			w.WriteString(fmt.Sprintf(cf_string_templates[1], param_key))
			for _, test_method := range test_methods {
				w.WriteString(fmt.Sprintf(cf_string_templates[2], test_method.test, test_method.method, test_method.paramValue))
			}
		}

		w.WriteString(df_string_templates[0])
		for data_flow, test_methods := range info.dataFlow {
			w.WriteString(fmt.Sprintf(df_string_templates[1], data_flow.msgField))
			w.WriteString(fmt.Sprintf(df_string_templates[2], data_flow.paramKey))
			for _, test_method := range test_methods {
				w.WriteString(fmt.Sprintf(df_string_templates[3], test_method.test, test_method.method, test_method.paramValue))
			}
		}

	}

	return nil
}

/*
 * Row: the message log (type and contents)
 * cur_ctype_params: params currently accessible (via methods currently being called)
 */
func (m *AllTaint) addFlow(test string, row []string, cur_ctype_params map[string][]MethodParams) {
	sending_goroutine := row[1]
	api_call_id_bytes := row[2]
	contents_bytes := row[3]

	api_call_id := APICallID{}
	err := json.Unmarshal([]byte(api_call_id_bytes), &api_call_id)
	if err != nil {
		log.Panicf("unmarshaling %v: %v\n", api_call_id_bytes, err.Error())
	}
	contents := []MsgField{}
	err = json.Unmarshal([]byte(contents_bytes), &contents)
	if err != nil {
		log.Panicf("unmarshaling %v: %v\n", contents_bytes, err.Error())
	}

	// Can't edit map value in place => get it (initializing its maps if needed) and put it back

	existing_flow := (*m)[api_call_id]
	if existing_flow.controlFlow == nil {
		existing_flow.controlFlow = make(map[string][]testMethod)
	}
	if existing_flow.dataFlow == nil {
		existing_flow.dataFlow = make(map[DataFlow][]testMethod)
	}

	// CF: Msg is CF-tainted by all params,
	// across all in-scope params for now -
	// TODO: should be only across the in-scope params of the goroutines in the sending one's spawn tree - need to track spawning for that
	for _, goroutine_params := range cur_ctype_params {
		for _, methodParam := range goroutine_params {
			for _, param := range methodParam.params {
				test_method := testMethod{test: test, method: methodParam.method, paramValue: param.Value}
				existing_flow.controlFlow[param.Key] = append(existing_flow.controlFlow[param.Key], test_method)
			}
		}
	}

	// DF: Msg field is DF-tainted by any params whose content match the field,
	// only considering the CType method that sent the msg (i.e. the most recent entry log from the sending goroutine)
	all_sending_params := cur_ctype_params[sending_goroutine]
	if len(all_sending_params) > 0 {
		cur_sending_params := all_sending_params[len(all_sending_params)-1]
		for _, param := range cur_sending_params.params {
			for _, field := range contents {
				if field.Value == param.Value {
					// TODO only compare params and fields that have the same type (requires logging type of both)
					data_flow := DataFlow{paramKey: param.Key, msgField: field.Key}
					test_method := testMethod{test: test, method: cur_sending_params.method, paramValue: param.Value}
					existing_flow.dataFlow[data_flow] = append(existing_flow.dataFlow[data_flow], test_method)
				}
			}
		}
	} else {
		// Send not from a CType method
	}

	(*m)[api_call_id] = existing_flow
}

// test_outfile contains output from one or more tests
// Combine all the output and put the result in result_outfile
// TODO write a unit test
func ParseTestOutput(test_outfile string, result_outfile string) error {
	file, err := os.Open(test_outfile)
	if err != nil {
		return err
	}
	defer file.Close()
	r := csv.NewReader(file)
	// Allow variable number of fields
	r.FieldsPerRecord = -1

	// Stack of in-scope methods and their params (last element = most recent), per goroutine
	cur_ctype_params := make(map[string][]MethodParams)
	msg_taint := make(AllTaint)
	cur_test := ""

	for {
		row, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			} else {
				// Ignore non-csv formatted lines for now (e.g. from a test log)
				// TODO separate conftamer logs from other test logs, and make conftamer logging tolerate t.Parallel()
				continue
			}
		}

		row_type := row[0]

		// Enter method
		if row_type == methodEntryLog {
			goroutine := row[1]
			method := row[2]
			params_bytes := row[3]
			params := []CTypeParam{}
			err := json.Unmarshal([]byte(params_bytes), &params)
			if err != nil {
				log.Panicf("unmarshaling %v: %v\n", params_bytes, err.Error())
			}
			cur_ctype_params[goroutine] = append(cur_ctype_params[goroutine], MethodParams{method: method, params: params})
		} else if row_type == methodExitLog {
			goroutine := row[1]
			// Pop the exited method's params (this also means we won't count messages not sent during any method)
			// Note this assumes params' influence ends when the method does, which isn't necc true -
			// e.g. influence can escape method via function return value, or goroutine spawned in method that persists beyond method exit
			cur_ctype_params[goroutine] = cur_ctype_params[goroutine][:len(cur_ctype_params[goroutine])-1]
		} else if row_type == MsgLog {
			msg_taint.addFlow(cur_test, row, cur_ctype_params)
		} else if strings.HasPrefix(row_type, "=== RUN") || strings.HasPrefix(row_type, "=== CONT") {
			fields := strings.Fields(row_type)
			test := fields[len(fields)-1]
			cur_test = test
		} else {
			// Some other test log
		}
	}

	msg_taint.prettyPrint(result_outfile)
	return nil
}
