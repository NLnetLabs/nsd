#!/bin/bash
. ../common.sh
get_random_port 1
SERVER_PORT=$RND_PORT
SERVER_HOST=127.0.0.1
ZONEFILE=dname_test.zone
NSD=../../nsd
PIDFILE=dname_test.pid
DIG="dig @$SERVER_HOST -p $SERVER_PORT"

count_zones=0
count_queries=0
count_checks=0

# start with -v to show more information
verbose=no
while getopts "v" x; do
	verbose=yes
done

# stop the server
function stop_server() {
	if test -f $PIDFILE; then
		kill_pid `cat $PIDFILE`
		rm nsd.log
		rm dname_test.db
	fi
}

# setup a server at SERVER_PORT on SERVER_HOST
# $1 is the config to use
function setup_server() {
	stop_server
	# start server
	if $NSD -V 3 -p $SERVER_PORT -c $1; then
		echo server started
		wait_nsd_up nsd.log
		return
	fi
	echo Error starting server
	stop_server
	exit 1
}

# pass name of config, name of header file and other RRs
function setup_zone_head() {
	local cfg=$1
	cp -f $2 $ZONEFILE
	shift
	shift
	while (($# > 0)); do
		echo $1 >> $ZONEFILE
		shift
	done
	if test $verbose = yes; then 
		cat $ZONEFILE
	fi
	((count_zones++))
	setup_server $cfg
}

# parameters are additional RRs to add to the zone.
function setup_zone() {
	setup_zone_head dname_test.conf zone_head "$@"
}

# setup a zone with long chain of C/DNAMES
# $1 DNAME or CNAME
# $2 length of chain (at least 1)
function setup_zone_chained() {
	echo chained zone $1 $2
	cp -f zone_head $ZONEFILE
	local i=0
	while (($i < $2)); do
		local j=`expr $i + 1`
		echo "x$i. $1 x$j" >> $ZONEFILE
		((i++))
	done
	echo "x$i A 10.0.0.10" >> $ZONEFILE
	echo "a.x$i A 10.0.0.10" >> $ZONEFILE
	if test $verbose = yes; then 
		cat $ZONEFILE
	fi
	((count_zones++))
	setup_server dname_test.conf
}

# run a query against the server 
# $1: query name
# $2: query type
function testquery() {
	echo testquery $1 $2
	if test $verbose = yes; then 
		echo $DIG $1 $2
	fi
	$DIG $1 $2 > query_output.temp
	if test $verbose = yes; then 
		cat query_output.temp
	fi
	((count_queries++))
}

# create regexp to filter for a RR
function rr_exp() {
	local e="^[^;]*"
	while (($# > 0)); do
		local f=`echo $1|sed -e 's/\./\\\./g'`
		e="$e.*$f"
		shift
	done
	rr_expr="$e"
}

# test if expectation is met
# arguments are and RR on a line that must be present
function testexpect() {
	local n=$*
	rr_exp $*
	((count_checks++))
	echo -n "expect:  "
	if grep $rr_expr query_output.temp; then
		return
	fi
	echo Error bad result from query, expected $n
	cat nsd.log
	stop_server
	exit 1
}

# check return code.
# $1: rc code
function testretcode() {
	local e="^;;.*HEADER.*opcode:.*, status: "$1
	((count_checks++))
	echo "expect:  "$1
	if grep "$e" query_output.temp >/dev/null; then
		return;
	fi
	grep HEADER query_output.temp
	echo Error bad return code from query, expected $1
	cat nsd.log
	stop_server
	exit 1
}

# check that an RR is not present
function testabsent() {
	rr_exp $*
	((count_checks++))
	echo -n "absent:  "
	if grep $rr_expr query_output.temp; then
		echo Error query contains RR $*
		stop_server
		exit 1
	fi
	echo $*
}

# do the tests

echo %%% 2.1 test 1
setup_zone "x. DNAME y." "foo.y. A 10.0.0.10"
testquery foo.x. A
testretcode NOERROR
testexpect x. DNAME y.
testexpect foo.x. CNAME foo.y.
testexpect foo.y. A 10.0.0.10
testquery foo.y. A
testretcode NOERROR
testexpect foo.y. A 10.0.0.10
testquery bar.x. A
testexpect x. DNAME y.
testexpect bar.x. CNAME bar.y.
testabsent foo.y. A 10.0.0.10
testretcode NXDOMAIN
testquery bar.y A
testabsent foo.y. A 10.0.0.10
testretcode NXDOMAIN
echo %%% 2.1 test 2
setup_zone "x. DNAME ." "foo. A 10.0.0.10"
testquery foo. A
testretcode NOERROR
testexpect foo. A 10.0.0.10
testquery foo.x. A
testretcode NOERROR
testexpect x. DNAME .
testexpect foo.x. CNAME foo.
testexpect foo. A 10.0.0.10
# looped
testquery foo.x.x. A
testretcode NOERROR
testexpect x. DNAME .
testexpect foo.x.x. CNAME foo.x.
testquery bar. A
testabsent foo. A 10.0.0.10
testretcode NXDOMAIN
testquery bar.x. A
testretcode NXDOMAIN
testexpect x. DNAME .
testexpect bar.x. CNAME bar.
testabsent foo. A 10.0.0.10
echo %%% 2.1 test 3
echo %%% 2.1 test 3: fails to zonec
#setup_zone ". DNAME x." "foo.x. A 10.0.0.10"

echo %%% 2.1 test 4
setup_zone "x. DNAME x.x." "foo. A 10.0.0.10"
testquery foo.x. A
testretcode NOERROR
testexpect x. DNAME x.x.
testexpect foo.x. CNAME foo.x.x.
testquery foo.x.x. A
testretcode NOERROR
testexpect x. DNAME x.x.
testexpect foo.x.x. CNAME foo.x.x.x.
testquery foo. A
testretcode NOERROR
testexpect foo. A 10.0.0.10
testabsent x. DNAME x.x.
testquery bar. A
testretcode NXDOMAIN
testabsent x. DNAME x.x.

echo %%% 2.1 test 5
setup_zone "x. DNAME x." "foo. A 10.0.0.10"
testquery foo.x. A
testretcode NOERROR
testexpect x. DNAME x.
testexpect foo.x. CNAME foo.x.
testquery foo. A
testretcode NOERROR
testabsent x. DNAME x.
testexpect foo. A 10.0.0.10

echo %%% 2.1 test 6
setup_zone "x.example.com. DNAME fooey.example.com." \
	"foo.fooey.example.com. A 10.0.0.10"
testquery foo.com. A
testretcode NXDOMAIN
testquery foo.x.example.com. A
testretcode NOERROR
testexpect x.example.com. DNAME fooey.example.com.
testexpect foo.x.example.com. CNAME foo.fooey.example.com.
testexpect foo.fooey.example.com. A 10.0.0.10
testquery foo.fooey.example.com. A
testretcode NOERROR
testexpect foo.fooey.example.com. A 10.0.0.10
testquery bar.x.example.com. A
testexpect x.example.com. DNAME fooey.example.com.
testexpect bar.x.example.com. CNAME bar.fooey.example.com.
testretcode NXDOMAIN
testquery bar.fooey.example.com. A
testretcode NXDOMAIN

echo %%% 2.1 test 7
setup_zone "fooey.example.com. DNAME x.example.com." \
	"foo.x.example.com. A 10.0.0.10"
testquery foo.example.com. A
testretcode NXDOMAIN
testquery foo.fooey.example.com. A
testretcode NOERROR
testexpect fooey.example.com. DNAME x.example.com.
testexpect foo.fooey.example.com. CNAME foo.x.example.com.
testexpect foo.x.example.com. A 10.0.0.10
testquery foo.x.example.com. A
testretcode NOERROR
testexpect foo.x.example.com. A 10.0.0.10
testquery bar.fooey.example.com. A
testexpect fooey.example.com. DNAME x.example.com.
testexpect bar.fooey.example.com. CNAME bar.x.example.com.
testretcode NXDOMAIN
testquery bar.x.example.com. A
testretcode NXDOMAIN

echo %%% 2.1 test 8
setup_zone "a.b.x. DNAME y." "foo.y. A 10.0.0.10"
testquery foo.a.b.x. A
testretcode NOERROR
testexpect a.b.x. DNAME y.
testexpect foo.a.b.x. CNAME foo.y.
testexpect foo.y. A 10.0.0.10
testquery foo.y. A
testretcode NOERROR
testexpect foo.y. A 10.0.0.10
testquery bar.a.b.x. A
testexpect a.b.x. DNAME y.
testexpect bar.a.b.x. CNAME bar.y.
testretcode NXDOMAIN
testquery bar.y. A
testretcode NXDOMAIN

echo %%% 2.1 test 9
setup_zone "x. DNAME a.b.y." "foo.a.b.y. A 10.0.0.10"
testquery foo.x. A
testretcode NOERROR
testexpect x. DNAME a.b.y.
testexpect foo.x. CNAME foo.a.b.y.
testexpect foo.a.b.y. A 10.0.0.10
testquery foo.a.b.y. A
testretcode NOERROR
testexpect foo.a.b.y. A 10.0.0.10
testquery bar.x. A
testexpect x. DNAME a.b.y.
testexpect bar.x. CNAME bar.a.b.y.
testretcode NXDOMAIN
testquery bar.a.b.y. A
testretcode NXDOMAIN

echo %%% 2.1 test 10
setup_zone "x. DNAME s171.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.long."
# very long
testquery foo.foo.foo.foo.foo.x. A
testexpect x. DNAME s171.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.long.
testexpect foo.foo.foo.foo.foo.x. CNAME foo.foo.foo.foo.foo.s171.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.very.long.
testretcode NXDOMAIN
# longer (62 + 171 = 233 or so)
testquery foo.foo.foo.foo.foo.foo.foo.f00.foo.foo.foo.foo.foo.foo.foo.x. A
testexpect x. DNAME
testexpect CNAME
testretcode NXDOMAIN
# too long (102 + 171 > 255)
testquery foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.x. A
testexpect x. DNAME
testabsent CNAME
testretcode YXDOMAIN

echo %%% 2.1 test 11
setup_zone "x.example.com. DNAME y.example.com." "foo.y.example.com. A 10.0.0.10"
testquery foo.x.example.com A
testretcode NOERROR
testexpect x.example.com. DNAME y.example.com.
testexpect foo.x.example.com. CNAME foo.y.example.com.
testexpect foo.y.example.com. A 10.0.0.10
testquery foo.y.example.com. A
testretcode NOERROR
testexpect foo.y.example.com. A 10.0.0.10
testquery bar.x.example.com. A
testexpect x.example.com. DNAME y.example.com.
testexpect bar.x.example.com. CNAME bar.y.example.com.
testretcode NXDOMAIN
testquery bar.y.example.com. A
testretcode NXDOMAIN

echo %%% 2.1 test 12
setup_zone "x. DNAME y." "y. A 10.0.0.10"
testquery x. A
testretcode NOERROR
testabsent A 10.0.0.10
testquery y. A
testretcode NOERROR
testexpect A 10.0.0.10

echo %%% 2.1 test 13
setup_zone "x. DNAME y." "x. A 10.0.0.10"
testquery x. A
testretcode NOERROR
testexpect A 10.0.0.10
testabsent x. DNAME y.
testquery y. A
testretcode NXDOMAIN
testabsent A 10.0.0.10

echo %%% 2.9
setup_zone "x. DNAME y." "a.y. A 10.0.0.10"
# test time is non0 for CNAME
testquery a.x. A
testexpect a.x. 3600 CNAME a.y.
testexpect a.y. A 10.0.0.10
# query for the CNAME
testquery a.x CNAME
testexpect a.x. CNAME a.y.
testretcode NOERROR
testquery b.x CNAME
testexpect b.x. CNAME b.y.
# because - Fix #148: CNAME need not be followed after a synthesized CNAME for a CNAME query.
# this is not NXDOMAIN but NOERROR
testretcode NOERROR

echo %%% 2.3. Wildcard
setup_zone "*.x. DNAME y." "a.y. A 10.0.0.10"
testquery x. A
testretcode NOERROR
testabsent x. DNAME
testabsent x. CNAME
testquery foo.x. A
testretcode NOERROR
testabsent x. DNAME
testabsent x. CNAME
testquery foo.a.x. A
testretcode NOERROR
testabsent x. DNAME
testabsent x. CNAME
testquery foo.a.a.x. A
testretcode NOERROR
testabsent x. DNAME
testabsent x. CNAME
testquery foo.*.x A
testretcode NXDOMAIN
testexpect \\*.x. DNAME y.
testexpect foo.\\*.x. CNAME foo.y.
testquery a.*.x A
testretcode NOERROR
testexpect \\*.x. DNAME y.
testexpect a.\\*.x. CNAME a.y.
testexpect a.y. A 10.0.0.10
setup_zone "x. DNAME bla.y." "*.y. A 10.0.0.10"
testquery x. A
testretcode NOERROR
testabsent x. DNAME
testabsent x. CNAME
testquery foo.x. A
testretcode NOERROR
testexpect x. DNAME bla.y.
testexpect foo.x. CNAME foo.bla.y.
testexpect foo.bla.y. A 10.0.0.10
testquery *.x. A
testretcode NOERROR
testexpect x. DNAME bla.y.
testexpect \\*.x. CNAME \\*.bla.y.
testexpect \\*.bla.y. A 10.0.0.10
testquery foo.bar.x. A
testretcode NOERROR
testexpect x. DNAME bla.y.
testexpect foo.bar.x. CNAME foo.bar.bla.y.
testexpect foo.bar.bla.y. A 10.0.0.10
testquery foo.*.x. A
testretcode NOERROR
testexpect x. DNAME bla.y.
testexpect foo.\\*.x. CNAME foo.\\*.bla.y.
testexpect foo.\\*.bla.y. A 10.0.0.10

echo %%% 2.4. CNAME
setup_zone "x. CNAME foo.y." "y. DNAME z." "foo.z. A 10.0.0.10"
testquery foo.x. A
testretcode NXDOMAIN
testabsent CNAME
testabsent DNAME
testquery bar.x. A
testretcode NXDOMAIN
testabsent CNAME
testabsent DNAME
testquery x. A
testretcode NOERROR
testexpect x. CNAME foo.y.
testexpect y. DNAME z.
testexpect foo.y. CNAME foo.z.
testexpect foo.z. A 10.0.0.10

setup_zone "x. DNAME y." "foo.y. CNAME othername.z." \
	"bar.y. CNAME bar.z." "othername.z. A 10.0.0.10"
testquery foo.x. A
testretcode NOERROR
testexpect x. DNAME y.
testexpect foo.x. CNAME foo.y.
testexpect foo.y. CNAME othername.z.
testexpect othername.z. A 10.0.0.10
testquery bar.x. A
testretcode NXDOMAIN
testexpect x. DNAME y.
testexpect bar.x. CNAME bar.y.
testexpect bar.y. CNAME bar.z.
testabsent A 10.0.0.10
testquery x. A
testretcode NOERROR
testabsent A 10.0.0.10
testabsent DNAME
testabsent CNAME

echo %%% 2.5. Chains
# try with 10
setup_zone_chained DNAME 10
testquery a.x0. A
testretcode NOERROR
testexpect a.x10. A 10.0.0.10
setup_zone_chained CNAME 10
testquery x0. A
testretcode NOERROR
testexpect x10. A 10.0.0.10
# try with 100
setup_zone_chained DNAME 100
testquery a.x0. A
testretcode NOERROR
testexpect a.x100. A 10.0.0.10
testquery foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.foo.x0 A
testretcode NOERROR
testexpect DNAME   # a partial answer
testexpect CNAME   # a partial answer
#testexpect foo.foo.x100. A 10.0.0.10
setup_zone_chained CNAME 100
testquery x0. A
testretcode NOERROR
testexpect x100. A 10.0.0.10
# try with 1000
setup_zone_chained DNAME 1000
testquery a.x0. A
testretcode NOERROR
testexpect DNAME   # a partial answer
testexpect CNAME   # a partial answer
#testexpect a.x1000. A 10.0.0.10
setup_zone_chained CNAME 1000
testquery x0. A
testretcode NOERROR
testexpect CNAME   # a partial answer
#testexpect x1000. A 10.0.0.10

# root DNAME setup
setup_zone "xn-blub. DNAME blub." "blub. NS ns1.blub" "ns1.blub. A 192.168.0.23"
testquery blub. A	# referral
testretcode NOERROR
testexpect blub. NS
testquery xn-blub. A    # nodata
testretcode NOERROR
testabsent blub. NS
testquery blub. SOA 	# referral
testretcode NOERROR
testexpect blub. NS
testquery xn-blub. SOA  # nodata
testretcode NOERROR
testquery foo.blub A	# referral
testretcode NOERROR
testexpect blub. NS
testquery foo.xn-blub A # referral
testexpect xn-blub. DNAME blub.
testretcode NOERROR
testexpect foo.xn-blub. CNAME foo.blub.
testexpect blub. NS

setup_zone "foo.xn-blub. CNAME foo.blub." "blub. NS ns1.blub" "ns1.blub. A 192.169.0.23"
testquery foo.xn-blub A	 # referral
testretcode NOERROR
testexpect foo.xn-blub. CNAME foo.blub.
testexpect blub. NS

setup_zone_head dname_test_x.conf zone_head_x "x. DNAME y."
testquery x. SOA
testretcode NOERROR
testabsent x. DNAME y.
testquery y. SOA
testretcode REFUSED
testabsent x. DNAME y.
testquery bla.x. A
testretcode NOERROR
testexpect x. DNAME y.
testquery bla.y. A
testretcode REFUSED
testabsent x. DNAME y.

echo %%% 2.6 Loops
setup_zone "x. DNAME y." "y. DNAME z." "z. DNAME y."
testquery foo.x. A
testretcode NOERROR
testexpect x. DNAME y.
testexpect y. DNAME z.
testexpect z. DNAME y.
testexpect foo.x. CNAME foo.y.
testexpect foo.y. CNAME foo.z.
testexpect foo.z. CNAME foo.y.

echo %%% 2.8 Invalid zones.
echo multiple DNAME zone
setup_zone "x	DNAME y.net." "x	DNAME z"
cat nsd.log
testquery . SOA
testretcode SERVFAIL

echo data below DNAME record
setup_zone "x	DNAME y.net." "foo.x	A	10.0.0.1"
cat nsd.log
testquery . SOA
testretcode SERVFAIL

echo 2.1. 3. . DNAME x. "(due to NS record)"
setup_zone ". NS ns.net." "ns.net. A 10.0.0.12" ".	DNAME y."
cat nsd.log
testquery . SOA
testretcode SERVFAIL

echo Second zone below DNAME record zone
setup_zone ". NS ns.net." "ns.net. A 10.0.0.12" "x.	DNAME y." "\$ORIGIN zone.x." "@ SOA ns.net h.net 20030203 2600 1800 2600 2600"
cat nsd.log
testquery . SOA
testretcode SERVFAIL

echo DNAME and CNAME at the same name.
setup_zone "x	DNAME y.example.com." "x	CNAME x.example.net."
cat nsd.log
testquery . SOA
testretcode SERVFAIL

# clean up
echo %%% all tests completed successfully
echo used $count_zones zones, $count_queries queries and $count_checks checks.
stop_server
exit 0
