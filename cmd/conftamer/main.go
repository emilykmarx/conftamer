package main

import (
	"flag"
	"fmt"

	"github.com/emilykmarx/conftamer"
)

/* Parse the output from a module's tests to produce the ConfTamer abstraction. */

func main() {
	var test_outfile, result_outfile string
	flag.StringVar(&test_outfile, "test-outfile", "test_out.log", "Path to file containing logging from tests")
	flag.StringVar(&result_outfile, "result-outfile", "result_out.log", "Path to file where abstraction will be written")
	flag.Parse()
	fmt.Printf("Parsing module logs from %v\nWriting output to %v\n", test_outfile, result_outfile)

	conftamer.ParseTestOutput(test_outfile, result_outfile)
}
