#!/bin/bash -ex

MODULE_PATH=/home/emily/projects/config_tracing/prometheus
MODULE_PREFIX=github.com/prometheus/prometheus
GOPLS_PATH=/home/emily/projects/config_tracing/golang.org-x-tools/gopls
UNMARSHAL_DEFN=/home/emily/go/pkg/mod/gopkg.in/yaml.v2@v2.4.0/yaml.go:32:6
UNMARSHALER_SUBGRAPH=$GOPLS_PATH/prom_results/tmp/unmarshaler_subgraph.text
ACCESSORS=$GOPLS_PATH/prom_results/tmp/accessors.text
OUTFILE=$GOPLS_PATH/prom_results/tmp/final_out.csv

# 1. Find CTypes graph
cd $GOPLS_PATH
go build .
cd $MODULE_PATH
$GOPLS_PATH/gopls -- conftamer \
	-u-defn $UNMARSHAL_DEFN \
	-m $MODULE_PREFIX \
	-u-out $UNMARSHALER_SUBGRAPH \
	-a-out $ACCESSORS

# 2. Run tests
cd $MODULE_PATH
pushd $GOPLS_PATH/internal/cmd/conftamer/dlv
go build .
popd

set +e
pkill dlv
set -e

# Choose test by setting test-pkg and test-name below - also adjust send-funcs and `modulemsginfo` import as needed
$GOPLS_PATH/internal/cmd/conftamer/dlv/dlv \
	--module-prefix=$MODULE_PREFIX \
	--unmarshaler-subgraph=$UNMARSHALER_SUBGRAPH \
	--accessors=$ACCESSORS \
	--test-pkg=$MODULE_PREFIX/scrape --test-name='^TestManagerCTZeroIngestion/format=PrometheusProto/withCT=false/ctZeroIngest=false$' \
	--send-funcs='net/http.(*Client).Do' \
	--outfile=$OUTFILE
