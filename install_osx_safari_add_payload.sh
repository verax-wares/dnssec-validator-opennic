#!/usr/bin/env sh

TAR_FILE=arch_$$.tar
TARGZ_FILE=${TAR_FILE}.gz

CURRENT_DIR=`pwd`

VERSION_FILE="Version"
if [ -f ${VERSION_FILE} ]; then
	VERSION=`cat ${VERSION_FILE}`
else
	VERSION="x.y.z"
fi

if [ "x${HWARCH}" = "x" ]; then
	HWARCH=unknown
fi

if [ "x${PKGS_DIR}" = "x" ]; then
	PKGS_DIR=packages
fi
if [ "x${SCRIPT_STUB}" = "x" ]; then
	SCRIPT_STUB=install_osx_safari_stub.sh
fi
if [ "x${TARGET_FILE}" = "x" ]; then
	TARGET_FILE="as-dnssec-tlsa-validator-${VERSION}-macosx-${HWARCH}.sh"
fi

if [ "x${PLUGIN_SRC_DIR}" = "x" ]; then
	PLUGIN_SRC_DIR=plugins-lib
fi
if [ "x${ADDON_SRC_DIR}" = "x" ]; then
	ADDON_SRC_DIR=add-on
fi

if [ "x${DNSSEC_DIR}" = "x" ]; then
	DNSSEC_DIR=npDNSSECValidatorPlugin.plugin
fi
if [ "x${TLSA_DIR}" = "x" ]; then
	TLSA_DIR=npTLSAValidatorPlugin.plugin
fi
if [ "x${SAFARIEXT}" = "x" ]; then
	SAFARIEXT=safari.safariextz
fi

function cleanup() {
	rm -f "${PLUGIN_SRC_DIR}/../${TAR_FILE}" "${PLUGIN_SRC_DIR}/../${TARGZ_FILE}" "${PKGS_DIR}/${TARGET_FILE}"
}

# Check whether target directory exists.
if [ ! -d "${PKGS_DIR}" ]; then
	mkdir ${PKGS_DIR} || exit 1
fi

# Preparation phase.
cleanup

# Create archive containing plug-in stuff.
if [ ! -d "${PLUGIN_SRC_DIR}/${DNSSEC_DIR}" ]; then
	echo "Directory ${PLUGIN_SRC_DIR}/${DNSSEC_DIR} does not exist." >&2
	cleanup
	exit 1
fi
cd "${PLUGIN_SRC_DIR}/"; tar -cf "../${TAR_FILE}" "./${DNSSEC_DIR}" ; cd "${CURRENT_DIR}"
if [ ! -d "${PLUGIN_SRC_DIR}/${TLSA_DIR}" ]; then
	echo "Directory ${PLUGIN_SRC_DIR}/${TLSA_DIR} does not exist." >&2
	cleanup
	exit 1
fi
cd "${PLUGIN_SRC_DIR}/"; tar -rf "../${TAR_FILE}" "./${TLSA_DIR}" ; cd "${CURRENT_DIR}"
if [ ! -f "${ADDON_SRC_DIR}/${SAFARIEXT}" ]; then
	echo "File ${ADDON_SRC_DIR}/${SAFARIEXT} does not exist." >&2
	cleanup
	exit 1
fi
cd "${ADDON_SRC_DIR}"; tar -rf "../${TAR_FILE}" "./${SAFARIEXT}" ; cd "${CURRENT_DIR}"
gzip "${PLUGIN_SRC_DIR}/../${TAR_FILE}"

cp "${SCRIPT_STUB}" "${PKGS_DIR}/${TARGET_FILE}"
echo "PAYLOAD:" >> "${PKGS_DIR}/${TARGET_FILE}"
cat "${PLUGIN_SRC_DIR}/../${TARGZ_FILE}" >> "${PKGS_DIR}/${TARGET_FILE}"
rm "${PLUGIN_SRC_DIR}/../${TARGZ_FILE}"

chmod +x "${PKGS_DIR}/${TARGET_FILE}"
