#!/bin/bash -eu
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
# Run the OSS-Fuzz script in the project.
if [ ! -f "/src/libultrahdr/allowlist.txt" ]; then
    export CFLAGS="${CFLAGS:-} -fno-inline-functions -fpass-plugin=/src/Function_instrument/libPrint_trace.so"
    export CXXFLAGS="${CXXFLAGS:-} -fno-inline-functions -fpass-plugin=/src/Function_instrument/libPrint_trace.so"
    export LDFLAGS="${LDFLAGS:-} /src/Function_instrument/print_func.o"
    $SRC/libultrahdr/fuzzer/ossfuzz.sh
    mkdir collect_trace
    mv /out/*fuzzer collect_trace/
fi

if [ -f "/src/libultrahdr/allowlist.txt" ]; then
    export CFLAGS="${CFLAGS:-} -fno-inline-functions  -fsanitize-coverage-allowlist=/src/libultrahdr/allowlist.txt"
    export CXXFLAGS="${CXXFLAGS:-} -fno-inline-functions -fsanitize-coverage-allowlist=/src/libultrahdr/allowlist.txt"
    $SRC/libultrahdr/fuzzer/ossfuzz.sh
fi