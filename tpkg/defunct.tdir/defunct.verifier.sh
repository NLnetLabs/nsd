#!/bin/sh

SERIAL=`dig @$VERIFY_IPV4_ADDRESS -p $VERIFY_IPV4_PORT $VERIFY_ZONE SOA +short +norec | awk '{print$3}'`
if [ $(( $SERIAL % 2 )) -eq 0 ]; then
	>&2 echo "Serial $SERIAL is even, exit with failure"
	exit 1
else
	echo "Serial $SERIAL is odd, exit with success"
	exit 0
fi
