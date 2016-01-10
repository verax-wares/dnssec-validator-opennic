#!/usr/bin/env sh

MAKE_CMD=make

./autogen.sh

rm -rf bits-32 bits-64 bits-fat
mkdir bits-32
mkdir bits-64
mkdir bits-fat

./configure --enable-static-linking --with-force-abi=x86
${MAKE_CMD} -C static-libs
cp static-libs/libs-built/ldns/lib/libldns.a bits-32/
cp static-libs/libs-built/openssl/lib/libcrypto.a bits-32/
cp static-libs/libs-built/openssl/lib/libssl.a bits-32/
cp static-libs/libs-built/unbound/lib/libunbound.a bits-32/
${MAKE_CMD} -C core_js-ctypes
mv core_js-ctypes/lib*core.dylib bits-32/
${MAKE_CMD} -C core_native-msg
mv core_native-msg/*-plug bits-32/


${MAKE_CMD} clean


./configure --enable-static-linking --with-force-abi=x86_64
${MAKE_CMD} -C static-libs
cp static-libs/libs-built/ldns/lib/libldns.a bits-64/
cp static-libs/libs-built/openssl/lib/libcrypto.a bits-64/
cp static-libs/libs-built/openssl/lib/libssl.a bits-64/
cp static-libs/libs-built/unbound/lib/libunbound.a bits-64/
${MAKE_CMD} -C core_js-ctypes
mv core_js-ctypes/lib*core.dylib bits-64/
${MAKE_CMD} -C core_native-msg
mv core_native-msg/*-plug bits-64/


# Manually create fat binaries.
lipo bits-32/libldns.a bits-64/libldns.a -create -output bits-fat/libldns.a
lipo bits-32/libcrypto.a bits-64/libcrypto.a -create -output bits-fat/libcrypto.a
lipo bits-32/libssl.a bits-64/libssl.a -create -output bits-fat/libssl.a
lipo bits-32/libunbound.a bits-64/libunbound.a -create -output bits-fat/libunbound.a
lipo bits-32/libDNSSECcore.dylib bits-64/libDNSSECcore.dylib -create -output bits-fat/libDNSSECcore.dylib
lipo bits-32/libDANEcore.dylib bits-64/libDANEcore.dylib -create -output bits-fat/libDANEcore.dylib
lipo bits-32/dnssec-plug bits-64/dnssec-plug -create -output bits-fat/dnssec-plug
lipo bits-32/dane-plug bits-64/dane-plug -create -output bits-fat/dane-plug
# Replace with fat targets.
cp bits-fat/libldns.a static-libs/libs-built/ldns/lib/libldns.a
cp bits-fat/libcrypto.a static-libs/libs-built/openssl/lib/libcrypto.a
cp bits-fat/libssl.a static-libs/libs-built/openssl/lib/libssl.a
cp bits-fat/libunbound.a static-libs/libs-built/unbound/lib/libunbound.a
cp bits-fat/libDNSSECcore.dylib core_js-ctypes/libDNSSECcore.dylib
cp bits-fat/libDANEcore.dylib core_js-ctypes/libDANEcore.dylib
cp bits-fat/dnssec-plug core_native-msg/dnssec-plug
cp bits-fat/dane-plug core_native-msg/dane-plug


./configure --enable-static-linking --with-force-abi=fat --enable-npapi-extensions
${MAKE_CMD} -C core_npapi

${MAKE_CMD} -C add-on
