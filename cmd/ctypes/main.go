package main

import (
	"flag"
	"fmt"

	"github.com/emilykmarx/conftamer/ctypesfinder"
)

/* Find a module's CTypes */

func main() {
	var module_src, result_outfile string
	flag.StringVar(&module_src, "module-src", "../prometheus/kubernetes", "Path to module source code")
	flag.StringVar(&result_outfile, "result-outfile", "result_out.log", "Path to file where CTypes will be written")
	flag.Parse()
	fmt.Printf("Analyzing module source from %v\nWriting output to %v\n", module_src, result_outfile)

	ctypesfinder.FindCTypes(module_src, result_outfile)
}
