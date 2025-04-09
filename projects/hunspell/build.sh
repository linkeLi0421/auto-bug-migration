#!/usr/bin/env bash

set -e

if [ -z "${OUT}" ] || [ -z "${SRC}" ] || [ -z "${WORK}" ]; then
    echo "OUT, SRC or WORK not set - script expects to be called inside oss-fuzz build env"
    exit 1
fi

if [ ! -f "/src/hunspell/allowlist.txt" ]; then
    export CFLAGS="$CFLAGS -fpass-plugin=/src/Function_instrument/libPrint_trace.so /src/Function_instrument/print_func.o"
    export CXXFLAGS="$CXXFLAGS -fpass-plugin=/src/Function_instrument/libPrint_trace.so /src/Function_instrument/print_func.o"

    autoreconf -vfi
    ./configure --disable-shared --enable-static
    make clean
    make -j$(nproc)
    mkdir collect_trace
    $CXX $CXXFLAGS -o collect_trace/fuzzer -I./src/ $LIB_FUZZING_ENGINE ./src/tools/fuzzer.cxx ./src/hunspell/.libs/libhunspell-1.7.a
    $CXX $CXXFLAGS -o collect_trace/affdicfuzzer -I./src/ $LIB_FUZZING_ENGINE ./src/tools/affdicfuzzer.cxx ./src/hunspell/.libs/libhunspell-1.7.a
fi

if [ -f "/src/hunspell/allowlist.txt" ]; then
    export CFLAGS="$CFLAGS -fsanitize-coverage-allowlist=/src/hunspell/allowlist.txt"
    export CXXFLAGS="$CXXFLAGS -fsanitize-coverage-allowlist=/src/hunspell/allowlist.txt"
    autoreconf -vfi
    ./configure --disable-shared --enable-static
    make clean
    make -j$(nproc)
    $CXX $CXXFLAGS -o $OUT/fuzzer -I./src/ $LIB_FUZZING_ENGINE ./src/tools/fuzzer.cxx ./src/hunspell/.libs/libhunspell-1.7.a
    $CXX $CXXFLAGS -o $OUT/affdicfuzzer -I./src/ $LIB_FUZZING_ENGINE ./src/tools/affdicfuzzer.cxx ./src/hunspell/.libs/libhunspell-1.7.a

    #dic/aff combos to test
    cp -f ./tests/arabic.* $OUT/
    cp -f ./tests/checkcompoundpattern*.* $OUT/
    cp -f ./tests/korean.* $OUT/
    cp -f ./tests/utf8*.* $OUT/
fi
