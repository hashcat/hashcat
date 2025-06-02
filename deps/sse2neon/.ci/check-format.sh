#!/usr/bin/env bash

. .ci/common.sh

set -x

for file in ${SOURCES};
do
    clang-format-18 ${file} > expected-format
    diff -u -p --label="${file}" --label="expected coding style" ${file} expected-format
done
exit $(clang-format-18 --output-replacements-xml ${SOURCES} | egrep -c "</replacement>")
