#!/bin/sh

if test -f verify_run.once; then
	echo "verifier script, no delay"
else
	echo "verifier script: delay"
	sleep 10
	touch verify_run.once
	echo "verifier script: delay done"
fi
exit 0
