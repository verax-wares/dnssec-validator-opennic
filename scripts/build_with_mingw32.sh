#!/usr/bin/env sh

SCRIPT_LOCATION=$(dirname $(readlink -f "$0"))
SRC_ROOT="${SCRIPT_LOCATION}/.."

cd "${SRC_ROOT}"

MINGW_PREFIX=i586-mingw32msvc # Unbound 1.5.1 requires patching.
#MINGW_PREFIX=i686-w64-mingw32 # Currently does not work.

# NPAPI extension was built directly oin Visual Studio.

CONF_OPTS=""
CONF_OPTS="${CONF_OPTS} --enable-static-linking"
#CONF_OPTS="${CONF_OPTS} --enable-npapi-extensions"
CONF_OPTS="${CONF_OPTS} --with-force-abi=x86"
CONF_OPTS="${CONF_OPTS} --host=${MINGW_PREFIX} --target=${MINGW_PREFIX}"

./configure ${CONF_OPTS}
make clean
make
#./scripts/install_chrome_add_payload.sh -C google-chrome
