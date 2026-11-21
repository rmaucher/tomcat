#!/bin/bash

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Run the HTTP/3 test suite and report a concise summary.
#
# Options:
#   --quiche            run against the quiche QUIC endpoint instead of the
#                       OpenSSL one (passes -Dtest.quiche=true, which makes
#                       the build select the Http3QuicheProtocol protocol
#                       class in the test JVM)
#   --quiche-lib DIR    directory holding libquiche.so (default: the pinned
#                       0.30.0 build below). Exported via LD_LIBRARY_PATH;
#                       not needed when libquiche is already reachable.
#   --ngtcp2            run against the ngtcp2 QUIC endpoint instead of the
#                       OpenSSL one (passes -Dtest.ngtcp2=true, which makes
#                       the build select the Http3Ngtcp2Protocol protocol
#                       class in the test JVM)
#   --ngtcp2-lib DIR    directory holding libngtcp2.so and
#                       libngtcp2_crypto_ossl.so (default: the system
#                       library path). Exported via LD_LIBRARY_PATH;
#                       not needed when the libraries are already reachable.
#
# Without --quiche or --ngtcp2 the tests run against the OpenSSL QUIC
# endpoint. The FFM OpenSSL bindings locate libssl via dlopen
# (java.library.path is not used unless the USE_SYSTEM_LOAD_LIBRARY property
# is set), so the OpenSSL library directory below is exported via
# LD_LIBRARY_PATH. Override with the OPENSSL_LIB_DIR environment variable, or
# point it at an empty/absent directory to keep OpenSSL out of the picture.
# The ngtcp2 endpoint uses the system OpenSSL by default, so the OpenSSL
# directory is removed from LD_LIBRARY_PATH in ngtcp2 mode (mixing an
# OpenSSL build with the system libssl the system libngtcp2 links against
# crashes the JVM).
cd "$(dirname "$0")" || exit 1
quiche=false
ngtcp2=false
quiche_lib=/home/opencode/quiche-0.30.0/target/release
ngtcp2_lib=""
openssl_lib=${OPENSSL_LIB_DIR:-/home/opencode/openssl-master}
ant_args=()
prev=""
for arg in "$@"; do
  if [ "$prev" = "--quiche-lib" ] || [ "$prev" = "-quiche-lib" ]; then
    quiche_lib="$arg"
    prev=""
    continue
  fi
  if [ "$prev" = "--ngtcp2-lib" ] || [ "$prev" = "-ngtcp2-lib" ]; then
    ngtcp2_lib="$arg"
    prev=""
    continue
  fi
  case "$arg" in
    --quiche|-quiche) quiche=true ;;
    --quiche-lib|-quiche-lib) prev=--quiche-lib ;;
    --ngtcp2|-ngtcp2) ngtcp2=true ;;
    --ngtcp2-lib|-ngtcp2-lib) prev=--ngtcp2-lib ;;
    *) ant_args+=("$arg") ;;
  esac
done
if $quiche && $ngtcp2; then
  echo "--quiche and --ngtcp2 are mutually exclusive" >&2
  exit 1
fi
# Print LD_LIBRARY_PATH with the given directory removed.
clean_ld_path() {
  local remove="$1" entry out=""
  local -a entries
  IFS=: read -r -a entries <<< "${LD_LIBRARY_PATH:-}"
  for entry in "${entries[@]}"; do
    [ -z "$entry" ] && continue
    [ "$entry" = "$remove" ] && continue
    out="${out:+$out:}$entry"
  done
  printf '%s' "$out"
}
if $quiche; then
  if [ ! -f "$quiche_lib/libquiche.so" ]; then
    echo "libquiche.so not found in $quiche_lib (use --quiche-lib DIR)" >&2
    exit 1
  fi
  export LD_LIBRARY_PATH="$quiche_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  ant_args+=(-Dtest.quiche=true)
elif $ngtcp2; then
  LD_LIBRARY_PATH=$(clean_ld_path "$openssl_lib")
  if [ -n "$ngtcp2_lib" ]; then
    if [ ! -f "$ngtcp2_lib/libngtcp2.so" ]; then
      echo "libngtcp2.so not found in $ngtcp2_lib (use --ngtcp2-lib DIR)" >&2
      exit 1
    fi
    if [ ! -f "$ngtcp2_lib/libngtcp2_crypto_ossl.so" ] &&
            [ ! -f "$ngtcp2_lib/libngtcp2_crypto_ossl.so.0" ]; then
      echo "libngtcp2_crypto_ossl.so not found in $ngtcp2_lib" >&2
      exit 1
    fi
    LD_LIBRARY_PATH="$ngtcp2_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  fi
  export LD_LIBRARY_PATH
  ant_args+=(-Dtest.ngtcp2=true)
else
  if [ -f "$openssl_lib/libssl.so" ] || [ -f "$openssl_lib/libssl.so.4" ]; then
    export LD_LIBRARY_PATH="$openssl_lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  else
    echo "libssl.so not found in $openssl_lib (OPENSSL_LIB_DIR); OpenSSL QUIC tests will skip" >&2
  fi
fi
rm -f output/build/logs/TEST-org.apache.coyote.http3.*.txt
ant test -Dtest.name="org/apache/coyote/http3/Test*.java" -Dtest.coverage=false "${ant_args[@]}" > /tmp/opencode/h3-test-run.log 2>&1
rc=$?
echo "=== exit=$rc ==="
for f in output/build/logs/TEST-org.apache.coyote.http3.*.NIO.txt; do
  [ -e "$f" ] || continue
  head -2 "$f" | tr '\n' ' '
  echo
done
grep -h "Tests run" output/build/logs/TEST-org.apache.coyote.http3.*.NIO.txt 2>/dev/null | awk -F'[:,]' '{r+=$2; f+=$4; e+=$6; s+=$8} END {printf "TOTAL run=%d failures=%d errors=%d skipped=%d\n", r, f, e, s}'
exit $rc
