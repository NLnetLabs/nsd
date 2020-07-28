#!/bin/sh

rm -f `ls -1a|grep -v '^socket10kxfr\.'|grep -v '^\.$'|grep -v '^\.\.$'`

