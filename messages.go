package conftamer

import (
	"encoding/csv"
	"encoding/json"
	"log"
	"os"
)

/* Functions modules should use to log API messages. */

const (
	methodEntryLog = "ENTER CTYPES METHOD"
	methodExitLog  = "EXIT CTYPES METHOD"
	MsgLog         = "MESSAGE"
)

// Uniquely identifies a sent or received API message.
// TODO some identifier of destination module (matters when a module can send same API messages to multiple modules)
type APICallID struct {
	API            string
	Verb           string
	Resource       string
	APIMessageType string
}

// Whether the message is a request or response
type APIMessageType string

const (
	Request  = "request"
	Response = "response"
)

// One field of a message's contents.
type MsgField struct {
	Key   string
	Value string
}

// Modules should call this when they send or receive an API message (on the sending/receiving goroutine).
// Log message info: which API call this message corresponds to, and contents
// TODO messages can be sent concurrently -
// check if csv writer is concurrency-safe, and match method entry/exit logs to message logs (log goroutine ID)
func LogAPIMessage(api_call_id APICallID, msg_contents []MsgField) {
	w := csv.NewWriter(os.Stdout)
	contents_bytes, err := json.Marshal(msg_contents)
	if err != nil {
		log.Panicf("marshaling %+v: %v\n", msg_contents, err.Error())
	}
	api_call_id_bytes, err := json.Marshal(api_call_id)
	if err != nil {
		log.Panicf("marshaling %+v: %v\n", api_call_id, err.Error())
	}
	w.WriteAll([][]string{
		{MsgLog, goid(), string(api_call_id_bytes), string(contents_bytes)},
	})
}

// Parse fields from any message type by json marshaling it.
// exclude: fields to be excluded (useful e.g. to ignore fields
// that are part of the API call ID rather than contents) -
// ignores entire value corresponding to first instance of the excluded key
// Note this will skip some but not all empty fields (due to how json.Marshal works)
func ParseJSONFields(msg_contents any, exclude map[string]struct{}) []MsgField {
	contents_bytes, err := json.Marshal(msg_contents)
	if err != nil {
		log.Panicf("marshaling %+v: %v\n", msg_contents, err.Error())
	}

	fields := []MsgField{}
	var contents_map map[string]interface{}
	json.Unmarshal(contents_bytes, &contents_map)
	// Each level of json nesting gives another map
	unnest(contents_map, &fields, "", exclude)
	return fields
}
