#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Build project
export LDSHARED=lld


if [ ! -f "/src/c-blosc2/allowlist.txt" ]; then
        cmake . -DCMAKE_C_FLAGS="$CFLAGS -fno-inline-functions -fpass-plugin=/src/Function_instrument/libPrint_trace.so /src/Function_instrument/print_func.o" -DCMAKE_CXX_FLAGS="$CXXFLAGS -fno-inline-functions -fpass-plugin=/src/Function_instrument/libPrint_trace.so /src/Function_instrument/print_func.o" \
                -DBUILD_FUZZERS=ON -DBUILD_TESTS=OFF -DBUILD_BENCHMARKS=OFF \
                -DBUILD_EXAMPLES=OFF -DBUILD_STATIC=ON -DBUILD_SHARED=OFF 

        make clean
        make -j$(nproc)
        mkdir collect_trace
        find . -name '*_fuzzer' -exec mv -v '{}' collect_trace ';'
fi

if [ -f "/src/c-blosc2/allowlist.txt" ]; then
        echo "Using allowlist from allowlist.txt"
        cmake . -DCMAKE_C_FLAGS="$CFLAGS -fno-inline-functions -fsanitize-coverage-allowlist=/src/c-blosc2/allowlist.txt" \
                -DCMAKE_CXX_FLAGS="$CXXFLAGS -fno-inline-functions -fsanitize-coverage-allowlist=/src/c-blosc2/allowlist.txt" \
                -DBUILD_FUZZERS=ON -DBUILD_TESTS=OFF -DBUILD_BENCHMARKS=OFF \
                -DBUILD_EXAMPLES=OFF -DBUILD_STATIC=ON -DBUILD_SHARED=OFF 

        make clean
        make -j$(nproc)

        # Package seed corpus
        zip -j "$OUT/decompress_chunk_fuzzer_seed_corpus.zip" compat/*.cdata
        zip -j "$OUT/decompress_frame_fuzzer_seed_corpus.zip" tests/fuzz/corpus/*

        # Copy the fuzzer executables, zip-ed corpora, and dictionary files to $OUT
        find . -name '*_fuzzer' -exec cp -v '{}' "$OUT" ';'
        find . -name '*_fuzzer.dict' -exec cp -v '{}' "$OUT" ';'
        find . -name '*_fuzzer_seed_corpus.zip' -exec cp -v '{}' "$OUT" ';'
fi
