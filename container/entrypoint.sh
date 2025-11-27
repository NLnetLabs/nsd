#!/bin/bash

if [ ! -d /storage/zones ]; then
	install -d -o nsd -g nsd -m 775 /storage/zones
fi

if [ ! -f /config/nsd_control.key ]; then
	nsd-control-setup
fi

nsd -d $NSD_OPTIONS
