#!/bin/bash -ex

MODULE_PATH=/home/emily/projects/config_tracing/prometheus
MODULE_PREFIX=github.com/prometheus/prometheus
GOPLS_PATH=/home/emily/projects/config_tracing/golang.org-x-tools
UNMARSHAL_DEFN=/home/emily/go/pkg/mod/gopkg.in/yaml.v2@v2.4.0/yaml.go:32:6
UNMARSHALER_SUBGRAPH=/home/emily/projects/config_tracing/golang.org-x-tools/gopls/prom_results/0622/unmarshaler_subgraph.text
ACCESSORS=/home/emily/projects/config_tracing/golang.org-x-tools/gopls/prom_results/0622/accessors.text

# 1. Find CTypes graph
cd $GOPLS_PATH/gopls
go build .
cd $MODULE_PATH
$GOPLS_PATH/gopls/gopls -- conftamer \
	-u-defn $UNMARSHAL_DEFN \
	-m $MODULE_PREFIX \
	-u-out $UNMARSHALER_SUBGRAPH \
	-a-out $ACCESSORS

# 2. Run tests
pushd $GOPLS_PATH/gopls/internal/cmd/conftamer/dlv
go build .
popd

set +e
pkill dlv
set -e

# Choose test by setting test-pkg and test-name below - also adjust send-funcs as needed
$GOPLS_PATH/gopls/internal/cmd/conftamer/dlv/dlv \
	--module-prefix=$MODULE_PREFIX \
	--unmarshaler-subgraph=$UNMARSHALER_SUBGRAPH \
	--accessors=$ACCESSORS \
	--test-pkg=/discovery/kubernetes --test-name=TestFailuresCountMetric \
	--send-funcs='k8s.io/client-go/testing.(*Fake).Invokes' --send-funcs='k8s.io/client-go/testing.(*Fake).InvokesWatch' --send-funcs='k8s.io/client-go/testing.(*Fake).InvokesProxy'
