package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
)

func CheckCmd(out []byte, err error) {
	if err != nil {
		fmt.Println(string(out))
		panic(err)
	}
}

func main() {
	var config_file string
	flag.StringVar(&config_file, "config", "", "Path to config file")
	flag.Parse()

	config, err := LoadConfig(config_file)
	CheckCmd(nil, err)

	// Setup
	out, err := exec.Command("mkdir", "-p", config.Results_path).CombinedOutput()
	CheckCmd(out, err)

	err = os.Chdir(config.Gopls_path)
	CheckCmd(nil, err)
	out, err = exec.Command("go", "build", ".").CombinedOutput()
	CheckCmd(out, err)

	// Find Unmarshaler Subgraph, and optionally Accessors
	err = os.Chdir(config.Module_path)
	CheckCmd(nil, err)
	gopls_cmd := []string{"--", "conftamer",
		"-u-defn", config.Unmarshal_fn,
		"-m", config.Module_prefix,
		"-u-out", config.Unmarshaler_subgraph,
	}
	if config.Accessors != "" {
		// Find Accessors too
		gopls_cmd = append(gopls_cmd, "-a-out", config.Accessors)
	}

	gopls := exec.Command(config.Gopls_path+"/gopls", gopls_cmd...)
	// get live results
	gopls.Stdout = os.Stdout
	gopls.Stderr = os.Stderr
	err = gopls.Run()
	CheckCmd(nil, err)
}
