# ConfTamer
- Interfaces and utilities for modules to implement ConfTamer by logging the required information:
  - CType methods (calls and corresponding CType parameters)
    - Currently done by modules - eventually will be auto-generated on modules' behalf
  - Sent and received API messages
    - Currently done by module tests (often via a mock API client/server package)
- Program to parse these logs and produce the ConfTamer abstraction for the module that logged them.

## Implementing ConfTamer in a module

Modules that implement ConfTamer (possibly via code generation tools and mock API clients/servers) must do the following:
- Implement the `CType` interface for each of their CTypes
- Call `LogCTypesMethodEntry()` and `LogCTypesMethodExit()` in each of their CTypes' methods
- Call `LogAPIMessage()` when sending or receiving an API message in a test

### Examples
- Our [fork](https://github.com/emilykmarx/prometheus) of Prometheus logs CType methods
- Our [fork](https://github.com/emilykmarx/client-go) of the Kubernetes test client logs API messages

## Producing the ConfTamer abstraction for a module
The module must implement ConfTamer as described above.

Run the modules' tests and save the logs to a file.
Then, run the `conftamer` tool on the log file.

```
go build ./cmd/conftamer
./conftamer --help
```
