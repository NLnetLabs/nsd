#!/bin/sh

PROXY="$1"
export PROXY

mkfifo "$PROXY/proxyin"
mkfifo "$PROXY/proxyout"
mkfifo "$PROXY/stdout"
mkfifo "$PROXY/stderr"

trap 'rm -f "$PROXY/proxyin" "$PROXY/proxyout" "$PROXY/stdout" "$PROXY/stderr" "$PROXY/stdin" "$PROXY/environment"; exit 0' 1 2 3 6 9 15

while test 1
do
	echo "Waiting for credns hook to be called..."
	read TRIGGER < "$PROXY/proxyin"
	if [ "$TRIGGER" = "Q" ]
	then
		echo Debugger terminated
		break
	fi
	. "$PROXY/environment"
	echo "Verifying request for $VERIFY_ZONE"
	echo "Write messages to $PROXY/stdout and error messages to $PROXY/stderr"
	echo "Exit with: exit <status>, where success means status == 0"
	echo "------------------------------------------------------------"
	bash --rcfile "$0.rc"
	STATUS=$?
	if [ "$STATUS" = "251" ]
	then
		echo "credns hook killed (timeout)"
		continue
	fi
	echo "------------------------------------------------------------"
	echo $STATUS > "$PROXY/proxyout"
done

rm -f "$PROXY/proxyin" "$PROXY/proxyout" "$PROXY/stdout" "$PROXY/stderr" "$PROXY/stdin" "$PROXY/environment"

