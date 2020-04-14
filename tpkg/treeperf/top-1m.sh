#!/bin/sh

#
# This script downloads and prepares the popularity list from Cisco for
# measurements with somewhat real-life data. Support for actual zone files
# should be added at a later point in time.
#
# http://s3-us-west-1.amazonaws.com/umbrella-static/index.html
# http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
#

for tool in wget unzip sed; do
  if ! which ${tool} >/dev/null; then
    echo "${tool} is unavailable" >&2
    exit 1
  fi
done

if wget http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip; then
  unzip top-1m.csv.zip
  mv top-1m.csv top-1m.list
  sed -i -e 's/^[0-9]\+\,//' top-1m.list
else
  exit 1
fi
