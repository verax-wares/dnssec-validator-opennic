#!/usr/bin/env sh


# Script must be run after these commands:
# ./configure && make


SCRIPT_LOCATION=""
#SYSTEM=`uname -s | tr '[:upper:]' '[:lower:]'`
SYSTEM=$(uname -s)
if [ ! "x${SYSTEM}" = "xDarwin" ]; then
	#SCRIPT=$(readlink -f "$0")
	SCRIPT_LOCATION=$(dirname $(readlink -f "$0"))
else
	SCRIPT_LOCATION=$(cd "$(dirname "$0")"; pwd)
fi
unset SYSTEM

SRC_ROOT="${SCRIPT_LOCATION}/.."
ADDON_DIR="${SRC_ROOT}/add-on"
ADDON_TMP_DIR="${ADDON_DIR}/__tmp__"
CORE_DIR="${SRC_ROOT}/core_native-msg"

SCRIPT_STUB="${SCRIPT_LOCATION}/install_chrome_stub.sh"
INSTALL_VARIABLES_FILE="${ADDON_DIR}/install_chrome_variables.sh"

DNSSEC_PKG="dnssec-pkg"
DNSSEC_CORE_NAME="dnssec-plug"
DNSSEC_BUILT_SRC_DIR="${ADDON_DIR}/_dtvcnm_workdir/dnssec"
DNSSEC_BUILT_JSON="${ADDON_DIR}/_dtvcnm_workdir/cz.nic.validator.dnssec.json.in"
DNSSEC_BUILT_CORE="${ADDON_DIR}/_dtvcnm_workdir/${DNSSEC_CORE_NAME}"
DNSSEC_PEM_NAME="chrome_dnssec_validator.pem"
DNSSEC_PEM="${SRC_ROOT}/../${DNSSEC_PEM_NAME}"

TLSA_PKG="tlsa-pkg"
TLSA_CORE_NAME="dane-plug"
TLSA_BUILT_SRC_DIR="${ADDON_DIR}/_dtvcnm_workdir/tlsa"
TLSA_BUILT_JSON="${ADDON_DIR}/_dtvcnm_workdir/cz.nic.validator.tlsa.json.in"
TLSA_BUILT_CORE="${ADDON_DIR}/_dtvcnm_workdir/${TLSA_CORE_NAME}"
TLSA_PEM_NAME="chrome_tlsa_validator.pem"
TLSA_PEM="${SRC_ROOT}/../${TLSA_PEM_NAME}"


OPTS="cCh"
GETOPT="cCh"

USAGE=""
USAGE="${USAGE}Usage:\n"
USAGE="${USAGE}\t$0 [-${OPTS}] chrome_executable\n"
USAGE="${USAGE}\n"
USAGE="${USAGE}Options:\n"
USAGE="${USAGE}\t-c\tPreserve generated CRX file.\n"
USAGE="${USAGE}\t-C\tPreserve generated CRX file and don't build installer script.\n"
USAGE="${USAGE}\t-h\tPrints this message.\n"
USAGE="${USAGE}\n"
USAGE="${USAGE}\tchrome_executable\n"
USAGE="${USAGE}\t\t-- name of the Chrome executable (e.g. chromium, google-chrome).\n"

PRESERVE_CTX="no"
BUILD_INSTALLER_SCRIPT="yes"

PACKAGE_VERSION="unknown_version"
OS_TARGET="unknown_os"
XPCOM_ABI_SUFF="-unknown_hwarch"

if [ -f "${INSTALL_VARIABLES_FILE}" ]; then
	. "${INSTALL_VARIABLES_FILE}"
else
	echo >&2 "Missing file '${INSTALL_VARIABLES_FILE}'. Build package content first."
fi

# Parse options.
set -- `getopt "${GETOPT}" "$@"`
if [ $# -lt 1 ]; then
	echo >&2 "Getopt failed."
	exit 1
fi
while [ $# -gt 0 ]; do
	case "$1" in
	-c)
		PRESERVE_CTX="yes"
		;;
	-C)
		PRESERVE_CTX="yes"
		BUILD_INSTALLER_SCRIPT="no"
		;;
	-h)
		echo >&2 -en "${USAGE}"
		exit 0
		;;
	--)
		shift
		break
		;;
	*)
		echo >&2 "Unknown option '$1'."
		exit 1
		;;
	esac
	shift
done


#CHROME_BINARY="google-chrome-stable"
#CHROME_BINARY="chromium"
if [ -z "${CHROME_BINARY}" ]; then
	# CHROME_BINARY may be passed via variable.
	if [ $# -ne 1 ]; then
		echo >&2 -ne "${USAGE}"
		exit 1
	fi
	CHROME_BINARY="$1"
fi


if ! type 1>/dev/null 2>&1 "${CHROME_BINARY}"; then
	echo >&2 "'${CHROME_BINARY}' is not a command."
	exit 1
fi


TARGZ_FILE=arch_$$.tar.gz
PACKAGES_DIR="${ADDON_DIR}"


TARGET_DNSSEC="${PACKAGES_DIR}/dnssec-plugin-${PACKAGE_VERSION}.x-${OS_TARGET}${XPCOM_ABI_SUFF}.sh"
DNSSEC_CRX="${PACKAGES_DIR}/gc-dnssec-validator-add-on-${PACKAGE_VERSION}.crx"
TARGET_TLSA="${PACKAGES_DIR}/tlsa-plugin-${PACKAGE_VERSION}.x-${OS_TARGET}${XPCOM_ABI_SUFF}.sh"
TLSA_CRX="${PACKAGES_DIR}/gc-tlsa-validator-add-on-${PACKAGE_VERSION}.crx"


#TEMP_DIR=`mktemp -d`
TEMP_DIR="${ADDON_TMP_DIR}"
rm -rf "${TEMP_DIR}" && mkdir "${TEMP_DIR}"


cleanup ()
{
	rm -rf "${TEMP_DIR}" "${TARGZ_FILE}" "${TARGET_DNSSEC}" "${TARGET_TLSA}"
}


cd "${TEMP_DIR}"

#cleanup
if [ ! -d "${DNSSEC_BUILT_SRC_DIR}" ]; then
	echo >&2 "Cannot find directory '${DNSSEC_BUILT_SRC_DIR}'."
	exit 1
fi
cp -r "${DNSSEC_BUILT_SRC_DIR}" "${TEMP_DIR}/${DNSSEC_PKG}"
cp "${DNSSEC_BUILT_JSON}" "${TEMP_DIR}/"
if [ ! -f "${DNSSEC_BUILT_CORE}" -a ! -f "${DNSSEC_BUILT_CORE}.exe" ]; then
	echo >&2 "Cannot find file '${DNSSEC_BUILT_CORE}[.exe]'."
	exit 1
fi
cp "${DNSSEC_BUILT_CORE}"* "${TEMP_DIR}/"
if [ ! -f "${DNSSEC_PEM}" ]; then
	echo >&2 "Cannot locate '${DNSSEC_PEM}'."
	exit 1
fi
cp "${DNSSEC_PEM}" "${TEMP_DIR}/"
"${CHROME_BINARY}" --pack-extension="${DNSSEC_PKG}" --pack-extension-key="${DNSSEC_PEM_NAME}"
rm "${TEMP_DIR}/${DNSSEC_PEM_NAME}"
#
if [ "x${BUILD_INSTALLER_SCRIPT}" = "xyes" ]; then
	tar -czf "${TARGZ_FILE}" cz.nic.validator.dnssec.json.in ${DNSSEC_CORE_NAME} ${DNSSEC_PKG}.crx
	cp "${SCRIPT_STUB}" "${TARGET_DNSSEC}"
	echo "PAYLOAD:" >> "${TARGET_DNSSEC}"
	cat "${TEMP_DIR}/${TARGZ_FILE}" >> "${TARGET_DNSSEC}"
	chmod +x "${TARGET_DNSSEC}"
	rm -f ${TARGZ_FILE}
fi

if [ "x${PRESERVE_CTX}" = "xyes" ]; then
	cp "${TEMP_DIR}/${DNSSEC_PKG}.crx" "${DNSSEC_CRX}"
fi
rm "${TEMP_DIR}/${DNSSEC_PKG}.crx"


cd "${TEMP_DIR}"

#cleanup
if [ ! -d "${TLSA_BUILT_SRC_DIR}" ]; then
	echo >&2 "Cannot find directory '${TLSA_BUILT_SRC_DIR}'."
	exit 1
fi
cp -r "${TLSA_BUILT_SRC_DIR}" "${TEMP_DIR}/${TLSA_PKG}"
cp "${TLSA_BUILT_JSON}" "${TEMP_DIR}/"
if [ ! -f "${TLSA_BUILT_CORE}" -a ! -f "${TLSA_BUILT_CORE}.exe" ]; then
	echo >&2 "Cannot find file '${TLSA_BUILT_CORE}'."
	exit 1
fi
cp "${TLSA_BUILT_CORE}"* "${TEMP_DIR}"
if [ ! -f "${TLSA_PEM}" ]; then
	echo >&2 "Cannot locate '${TLSA_PEM}'."
	exit 1
fi
cp "${TLSA_PEM}" "${TEMP_DIR}/"
"${CHROME_BINARY}" --pack-extension="${TLSA_PKG}" --pack-extension-key="${TLSA_PEM_NAME}"
rm "${TEMP_DIR}/${TLSA_PEM_NAME}"
#
if [ "x${BUILD_INSTALLER_SCRIPT}" = "xyes" ]; then
	tar -czf "${TARGZ_FILE}" cz.nic.validator.tlsa.json.in ${TLSA_CORE_NAME} ${TLSA_PKG}.crx
	cp "${SCRIPT_STUB}" "${TARGET_TLSA}"
	echo "PAYLOAD:" >> "${TARGET_TLSA}"
	cat "${TEMP_DIR}/${TARGZ_FILE}" >> "${TARGET_TLSA}"
	chmod +x "${TARGET_TLSA}"
	rm -f ${TARGZ_FILE}
fi

if [ "x${PRESERVE_CTX}" = "xyes" ]; then
	cp "${TEMP_DIR}/${TLSA_PKG}.crx" "${TLSA_CRX}"
fi
rm "${TEMP_DIR}/${TLSA_PKG}.crx"


rm -rf ${TEMP_DIR}
