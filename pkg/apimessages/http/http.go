package http

import (
	"strings"

	"github.com/emilykmarx/conftamer/pkg/apimessages"
	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

// For HTTP requests
func GetMessageInfo(client *rpc2.RPCClient, bp *api.Breakpoint, send_goroutine int64) (*apimessages.APICallID, error) {
	loadcfg := api.LoadConfig{FollowPointers: true, MaxVariableRecurse: 10, MaxStringLen: 10, MaxArrayValues: 1, MaxStructFields: -1}
	scope := api.EvalScope{GoroutineID: send_goroutine}
	verb, err := client.EvalVariable(scope, "req.Method", loadcfg)
	if err != nil {
		return nil, err
	}
	resource, err := client.EvalVariable(scope, "req.URL.Path", loadcfg)
	if err != nil {
		return nil, err
	}
	api, err := client.EvalVariable(scope, "req.Header[\"User-Agent\"][0]", loadcfg)
	if err != nil {
		return nil, err
	}

	api_call_id := apimessages.APICallID{
		API:            api.Value,
		Verb:           strings.ToUpper(verb.Value),
		Resource:       resource.Value,
		APIMessageType: apimessages.Request,
	}

	return &api_call_id, nil
}
