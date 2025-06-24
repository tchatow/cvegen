#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage <location> <name>"
    exit 1
fi

set -o xtrace
set -e

cvegen_loc=$(pwd)

pushd $1
# mvn clean
#JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64/ codeql database create "$cvegen_loc/codeql/$2" --overwrite --language java #--command='ant -f build.xml'
popd

codeql query run codeql/queries/codeql-custom-queries-java/harnessReachable.ql -d "codeql/$2" -o "codeql/$2-harness.bqrs"
codeql bqrs decode "codeql/$2-harness.bqrs" --format json -o "codeql/$2-harness.json"
codeql query run codeql/queries/codeql-custom-queries-java/parentClasses.ql -d "codeql/$2" -o "codeql/$2-parents.bqrs"
codeql bqrs decode "codeql/$2-parents.bqrs" --format json -o "codeql/$2-parents.json"
codeql query run codeql/queries/codeql-custom-queries-java/callsFileOps.ql -d "codeql/$2" -o "codeql/$2-fuzz-reachable.bqrs"
codeql bqrs decode "codeql/$2-fuzz-reachable.bqrs" --format json -o "codeql/$2-fuzz-reachable.json"