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
func (m *AllTaint) addFlow(test string, row []string, cur_ctype_params []MethodParams) {
	api_call_id_bytes := row[1]
	contents_bytes := row[2]

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

	for _, methodParam := range cur_ctype_params {
		for _, param := range methodParam.params {
			test_method := testMethod{test: test, method: methodParam.method, paramValue: param.Value}

			// CF: Msg is CF-tainted by all params
			// TODO add param.Value to AllTaint for pretty-printing
			existing_flow.controlFlow[param.Key] = append(existing_flow.controlFlow[param.Key], test_method)

			// DF: Msg field is DF-tainted by any params whose content match the field
			for _, field := range contents {
				if field.Value == param.Value {
					// TODO only compare params and fields that have the same type (requires logging type of both)
					data_flow := DataFlow{paramKey: param.Key, msgField: field.Key}
					existing_flow.dataFlow[data_flow] = append(existing_flow.dataFlow[data_flow], test_method)
				}
			}
		}

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

	// Stack of in-scope methods and their params (last element = most recent)
	cur_ctype_params := []MethodParams{}
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

		// Enter method
		if row[0] == methodEntryLog {
			// TODO nested methods: if same CType, doesn't matter - but if different CTypes, take union of params?
			params := []CTypeParam{}
			err := json.Unmarshal([]byte(row[2]), &params)
			if err != nil {
				log.Panicf("unmarshaling %v: %v\n", row[2], err.Error())
			}
			cur_ctype_params = append(cur_ctype_params, MethodParams{method: row[1], params: params})
		} else if row[0] == methodExitLog {
			// Pop the exited method's params (this also means we won't count messages not sent during any method)
			// Note this assumes params' influence ends when the method does, which isn't necc true -
			// e.g. influence can escape method via function return value, or goroutine spawned in method that persists beyond method exit
			cur_ctype_params = cur_ctype_params[:len(cur_ctype_params)-1]
		} else if row[0] == MsgLog {
			msg_taint.addFlow(cur_test, row, cur_ctype_params)
		} else if strings.HasPrefix(row[0], "=== RUN") || strings.HasPrefix(row[0], "=== CONT") {
			fields := strings.Fields(row[0])
			test := fields[len(fields)-1]
			cur_test = test
		} else {
			// Some other test log
		}
	}

	msg_taint.prettyPrint(result_outfile)
	return nil
}
