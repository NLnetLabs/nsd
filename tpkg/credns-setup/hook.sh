#!/bin/sh

PROXY="$1"


if [ -p "$PROXY/proxyin" -a -p "$PROXY/proxyout" \
  -a -p "$PROXY/stdout"  -a -p "$PROXY/stderr"   ]
then
	( for ENVVAR in VERIFY_ZONE \
			VERIFY_ZONE_ON_STDIN \
			VERIFY_IP_ADDRESSES  \
			VERIFY_IP_ADDRESS   VERIFY_PORT      \
			VERIFY_IPV6_ADDRESS VERIFY_IPV6_PORT \
			VERIFY_IPV4_ADDRESS VERIFY_IPV4_PORT
	  do
		printf "%s" "$ENVVAR=\""
		eval echo \$$ENVVAR \
		| sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/$/"/g'
		echo "export $ENVVAR"
	  done
	) > "$PROXY/environment"
	tail -f "$PROXY/stdout" &
	CPSTDOUT=$!
	tail -f "$PROXY/stderr" 1>&2 &
	CPSTDERR=$!
	if [ "$VERIFY_ZONE_ON_STDIN" = "yes" ]
	then
		cat > "$PROXY/stdin"
	else
		rm -f "$PROXY/stdin"
	fi
	echo R > "$PROXY/proxyin"
	read DEBUGBASHPID < "$PROXY/proxyout"
	echo Debug bash is on $DEBUGBASHPID
	trap "echo Sending $DEBUGBASHPID the kill signal; kill $DEBUGBASHPID; kill $CPSTDOUT; kill $CPSTDERR; exit 251" 1 2 3 6 9 15
	read STATUS < "$PROXY/proxyout"
	kill $CPSTDOUT > /dev/null 2>/dev/null
	kill $CPSTDERR > /dev/null 2>/dev/null
	exit $STATUS
else
	echo No debugger listening... 1>&2
	exit 250
fi

