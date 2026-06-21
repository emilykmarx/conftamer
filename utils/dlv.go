package contexttrack

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-delve/delve/service/rpc2"
)

type ErrNoTests struct {
}

func (err *ErrNoTests) Error() string {
	return "no test files"
}

func waitForServer(stdout *saveOutput, stderr *saveOutput) error {
	// Wait for server to start or error
	for ; len(stdout.savedOutput) == 0 && len(stderr.savedOutput) == 0; time.Sleep(300 * time.Millisecond) {
	}
	if len(stderr.savedOutput) > 0 {
		fmt.Printf("DLV STDERR: %v\n", string(stderr.savedOutput))
		fmt.Printf("DLV STDOUT: %v\n", string(stdout.savedOutput))

		if strings.Contains(string(stderr.savedOutput), "could not launch process: not an executable file") {
			return &ErrNoTests{}
		}
		if !strings.Contains(string(stderr.savedOutput), "CGO_CFLAGS already set, Cgo code could be optimized.") {
			return fmt.Errorf("Delve server errored while starting up - stderr above")
		}
	}
	// Wait for server to start if stderr was a false alarm
	for ; len(stdout.savedOutput) == 0; time.Sleep(300 * time.Millisecond) {
	}
	if !strings.HasPrefix(string(stdout.savedOutput), "API server listening at:") {
		fmt.Printf("DLV STDERR: %v\n", string(stderr.savedOutput))
		fmt.Printf("DLV STDOUT: %v\n", string(stdout.savedOutput))

		if strings.Contains(string(stdout.savedOutput), "[no test files]") {
			// Sometimes the stderr message for this shows up first and sometimes the stdout one
			return &ErrNoTests{}
		}
		// happens if endpoint already bound
		return fmt.Errorf("Delve server failed to start listening - stdout above")
	}

	return nil
}

// Allows writing child process' output to stdout and also parsing it
type saveOutput struct {
	savedOutput []byte
}

func (so *saveOutput) Write(p []byte) (n int, err error) {
	so.savedOutput = append(so.savedOutput, p...)
	return os.Stdout.Write(p)
}

// Launch the given test under dlv.
// Run a client that connects to the dlv instance.
func Run(dlv_port int, test_pkg string, test_name string, client_data any, client_func func(string, any) error) error {
	dlv_endpoint := fmt.Sprintf("localhost:%v", dlv_port)

	// Start dlv server
	dlv_server, cancel, server_stdout, server_stderr := DlvServerCmd(dlv_endpoint, test_pkg, test_name)
	defer cancel()

	err := dlv_server.Start()
	if err != nil {
		return fmt.Errorf("Dlv server failed to launch: %v\n", err.Error())
	}
	err = waitForServer(server_stdout, server_stderr)
	if err != nil {
		return err
	}

	// Run dlv client until test finishes
	if err := client_func(dlv_endpoint, client_data); err != nil {
		return err
	}

	// Check server stderr for problems during test
	if len(server_stderr.savedOutput) > 0 {
		server_lines := strings.Split(strings.Trim(string(server_stderr.savedOutput), "\n"), "\n")
		if len(server_lines) == 1 && strings.Contains(server_lines[0], "Listening for remote connections") {
			// normal
		} else {
			return fmt.Errorf("Delve server errored while client running: %s", server_stderr.savedOutput)
		}
	}
	return nil
}

func DlvServerCmd(dlv_endpoint string, test_pkg string, test_name string) (*exec.Cmd, context.CancelFunc, *saveOutput, *saveOutput) {
	ctx, cancel := context.WithCancel(context.Background())

	server := exec.CommandContext(ctx, "dlv", "test", "--headless",
		"--api-version=2", "--accept-multiclient", "--listen", dlv_endpoint,
		test_pkg, "--", "-test.v", "-test.run", test_name)

	fmt.Printf("Starting server: %v\n", strings.Join(server.Args, " "))

	var server_out, server_err saveOutput
	server.Stdout = &server_out
	server.Stderr = &server_err

	return server, cancel, &server_out, &server_err
}

// Connect to dlv and run the test
func RunClient(dlv_endpoint string) error {
	fmt.Printf("Connecting to dlv on %v\n", dlv_endpoint)

	client := rpc2.NewClient(dlv_endpoint)
	state := <-client.Continue()

	for ; !state.Exited; state = <-client.Continue() {
		if state.Err != nil {
			return fmt.Errorf("Error in debugger state: %v\n", state.Err)
		}
	}

	fmt.Printf("Target exited with status %v\n", state.ExitStatus)

	return nil
}
