#!/usr/bin/env sh

USAGE="Usage: configure.sh [debug|help]"

CONF_OPTS="
	--enable-static-linking \
	"

if [ "x$1" != "x" ]; then
	for param in $@; do
		case ${param} in
		debug)
			CONF_OPTS="${CONF_OPTS} --enable-debug"
			;;
		help)
			echo ${USAGE}
			exit
			;;
		*)
			echo ${USAGE} >&2
			exit 1
			;;
		esac
	done
fi

CMD="./configure ${CONF_OPTS}"

echo ${CMD}
${CMD}
