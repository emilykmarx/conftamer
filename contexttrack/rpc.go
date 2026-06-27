// Generic methods for invoking the Delve RPC server and interpreting outputs.
package contexttrack

import (
	"fmt"
	"strings"

	"github.com/go-delve/delve/service/api"
	"github.com/go-delve/delve/service/rpc2"
)

type DelveClient struct {
	c *rpc2.RPCClient
}

func NewDelveClient(addr string) *DelveClient {
	fmt.Printf("Connecting to Delve at %s…\n", addr)
	return &DelveClient{c: rpc2.NewClient(addr)}
}

func (d *DelveClient) FindLocation(loc string) ([]api.Location, error) {
	scope := api.EvalScope{GoroutineID: -1, Frame: 0, DeferredCall: 0}
	locs, _, err := d.c.FindLocation(scope, loc, false, nil)
	return locs, err
}

func (d *DelveClient) CreateBreakpoint(addr uint64) (*api.Breakpoint, error) {
	return d.c.CreateBreakpoint(&api.Breakpoint{Addr: addr})
}

func (d *DelveClient) Continue() *api.DebuggerState {
	return <-d.c.Continue()
}

func (d *DelveClient) Stacktrace(goroutineID int) ([]api.Stackframe, error) {
	return d.c.Stacktrace(int64(goroutineID), StackDepth, 0, 0, &LoadCfg)
}

func (d *DelveClient) ListFunctionArgs(goroutineID, frame int) ([]api.Variable, error) {
	scope := api.EvalScope{GoroutineID: int64(goroutineID), Frame: frame}
	return d.c.ListFunctionArgs(scope, LoadCfg)
}

func (d *DelveClient) ListLocalVars(goroutineID, frame int) ([]api.Variable, error) {
	scope := api.EvalScope{GoroutineID: int64(goroutineID), Frame: frame}
	return d.c.ListLocalVariables(scope, LoadCfg)
}

func (d *DelveClient) EvalVariable(goroutineID, frame int, expr string) (*api.Variable, error) {
	scope := api.EvalScope{GoroutineID: int64(goroutineID), Frame: frame}
	return d.c.EvalVariable(scope, expr, LoadCfg)
}

// SetBreakpointsFor resolves funcName to addresses and creates a breakpoint at each.
// Returns the set of breakpoint IDs created (nil if none found).
func SetBreakpointsFor(client *DelveClient, funcName, name string) map[int]bool {
	locs, err := client.FindLocation(funcName)
	if err != nil || len(locs) == 0 {
		fmt.Printf("  WARNING: no locations found for %q — skipping\n", funcName)
		return nil
	}
	ids := make(map[int]bool)
	for _, loc := range locs {
		bp, err := client.CreateBreakpoint(loc.PC)
		if err != nil {
			fmt.Printf("  WARNING: [%s] failed to create breakpoint at 0x%x: %v\n", name, loc.PC, err)
			continue
		}
		ids[bp.ID] = true
		fmt.Printf("  [%s] Breakpoint %d at %s:%d (0x%x) for %q\n",
			name, bp.ID, bp.File, bp.Line, loc.PC, funcName)
	}
	return ids
}

// GetAllFrameVars returns the union of function args and local variables for the given frame.
func GetAllFrameVars(client *DelveClient, goroutineID, frame int) []api.Variable {
	var result []api.Variable
	if args, err := client.ListFunctionArgs(goroutineID, frame); err == nil {
		result = append(result, args...)
	}
	if vars, err := client.ListLocalVars(goroutineID, frame); err == nil {
		result = append(result, vars...)
	}
	return result
}

// FlatValue returns a one-line summary of a Delve variable.
func FlatValue(v *api.Variable) string {
	if v.Value != "" {
		return v.Value
	}
	if len(v.Children) == 0 {
		return fmt.Sprintf("(%s)", v.Type)
	}
	var parts []string
	for _, c := range v.Children {
		if c.Value != "" {
			parts = append(parts, fmt.Sprintf("%s:%s", c.Name, c.Value))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("(%s …)", v.Type)
	}
	n := min(5, len(parts))
	snippet := strings.Join(parts[:n], " ")
	if len(parts) > 5 {
		snippet += " …"
	}
	return "{" + snippet + "}"
}

// PrintVariable recursively prints a Delve variable tree.
func PrintVariable(v *api.Variable, prefix, childPrefix string, depth int) {
	if v == nil || depth > 6 {
		return
	}
	typeStr := ""
	if v.Type != "" {
		typeStr = fmt.Sprintf(" (%s)", v.Type)
	}
	if v.Value != "" {
		fmt.Printf("%s%s%s = %s\n", prefix, v.Name, typeStr, v.Value)
	} else if len(v.Children) > 0 {
		fmt.Printf("%s%s%s:\n", prefix, v.Name, typeStr)
		for i := range v.Children {
			PrintVariable(&v.Children[i], childPrefix, childPrefix+"  ", depth+1)
		}
	} else {
		fmt.Printf("%s%s%s\n", prefix, v.Name, typeStr)
	}
}
