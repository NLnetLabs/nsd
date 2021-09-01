AC_INIT(credns-setup, 0.01, willem@nlnetlabs.nl)

AC_ARG_VAR(DEFAULT_IP, 
	   Default IP address for all nameservers (default 127.0.0.1))
if test "x$DEFAULT_IP" = "x" ; then DEFAULT_IP=127.0.0.1 ; fi

AC_ARG_VAR(MASTER, Name of the hidden master (default: master))
if test "x$MASTER" = "x" ; then MASTER=master ; fi

AC_ARG_VAR(MASTER_IP, 
	   IP address on which the hidden master listens (default: DEFAULT_IP))
if test "x$MASTER_IP" = "x" ; then MASTER_IP=$DEFAULT_IP ; fi

AC_ARG_VAR(MASTER_PORT, 
	   Port on which the hidden master listens (default: 53470))
if test "x$MASTER_PORT" = "x" ; then MASTER_PORT=53470 ; fi

AC_ARG_VAR(MASTER_CONTROL_PORT, 
	   Port on which the hidden master can be controlled (default: 53471))
if test "x$MASTER_CONTROL_PORT" = "x" ; then MASTER_CONTROL_PORT=53471 ; fi

AC_ARG_VAR(PROXY, Name for the credns proxy server (default: proxy))
if test "x$PROXY" = "x" ; then PROXY=proxy ; fi

AC_ARG_VAR(PROXY_IP, 
	   IP address for the credns proxy server (default: DEFAULT_IP))
if test "x$PROXY_IP" = "x" ; then PROXY_IP=$DEFAULT_IP ; fi

AC_ARG_VAR(PROXY_PORT, Port for the credns proxy server (default: 53473))
if test "x$PROXY_PORT" = "x" ; then PROXY_PORT=53473 ; fi

AC_ARG_VAR(PROXY_CONTROL_PORT, 
	   Port on which the credns proxy server can be controlled (default: 53474))
if test "x$PROXY_CONTROL_PORT" = "x" ; then PROXY_CONTROL_PORT=53474 ; fi

AC_ARG_VAR(SLAVE, Name of the public slave (default: slave))
if test "x$SLAVE" = "x" ; then SLAVE=slave ; fi

AC_ARG_VAR(SLAVE_IP, 
	   IP address on which the public slave listens (default: DEFAULT_IP))
if test "x$SLAVE_IP" = "x" ; then SLAVE_IP=$DEFAULT_IP; fi

AC_ARG_VAR(SLAVE_PORT, Port on which the public slave listens (default: 53476))
if test "x$SLAVE_PORT" = "x" ; then SLAVE_PORT=53476 ; fi

AC_ARG_VAR(SLAVE_CONTROL_PORT, 
	   Port on which the public slave can be controlled (default: 53477))
if test "x$SLAVE_CONTROL_PORT" = "x" ; then SLAVE_CONTROL_PORT=53477 ; fi

AC_ARG_VAR(VERIFY_IP, 
	   IP address for querying the zone to be assessed (default: PROXY_IP))
if test "x$VERIFY_IP" = "x" ; then VERIFY_IP=$PROXY_IP ; fi

AC_ARG_VAR(VERIFY_PORT, Port for querying the zone to be assessed (default: 5347))
if test "x$VERIFY_PORT" = "x" ; then VERIFY_PORT=5347 ; fi

AC_ARG_VAR(ZONE, Zone to serve (default: credns.test))
if test "x$ZONE" = "x"; then ZONE=credns.test; fi

AC_ARG_VAR(NZONES, Number of zones to serve (default: 1))
if test "x$NZONES" = "x"; then NZONES=1; fi

AC_ARG_VAR(SERIAL, Initial serial of SOA RR (default: 1))
if test "x$SERIAL" = "x"; then SERIAL=1 ; fi

AC_ARG_VAR(REFRESH, Initial refresh time of SOA RR (default: 120 (2 minutes)))
if test "x$REFRESH" = "x"; then REFRESH=120 ; fi

AC_ARG_VAR(RETRY, Initial retry time of SOA RR (default: 30 (0.5 minutes)))
if test "x$RETRY" = "x"; then RETRY=30 ; fi

AC_ARG_VAR(EXPIRE, Initial expire time of SOA RR (default: 180 (3 minutes)))
if test "x$EXPIRE" = "x"; then EXPIRE=180; fi

AC_ARG_VAR(MINIMUM, Initial minimum time of SOA RR (default: 75 (1.25 minutes)))
if test "x$MINIMUM" = "x"; then MINIMUM=75; fi

AC_ARG_VAR(TTL, Time to live (TTL) for zone RRs (default: 30 (0.5 minute)))
if test "x$TTL" = "x"; then TTL=30; fi

AC_ARG_VAR(RELOAD_TIMEOUT, Throttles the reloads to once per the number of seconds (default: 2))
if test "x$RELOAD_TIMEOUT" = "x"; then RELOAD_TIMEOUT=2; fi

AC_ARG_VAR(VERBOSITY, Verbosity in log files (default: 1))
if test "x$VERBOSITY" = "x"; then VERBOSITY=1; fi

AC_ARG_VAR(VERIFIER_COUNT, Number of verifiers to run simultaneously (default: 1))
if test "x$VERIFIER_COUNT" = "x"; then VERIFIER_COUNT=1; fi

AC_ARG_VAR(VERIFIER_FEED_ZONE, Feed zone on stdin (default: yes))
if test "x$VERIFIER_FEED_ZONE" = "x"; then VERIFIER_FEED_ZONE=yes; fi

AC_ARG_VAR(VERIFIER_TIMEOUT, How long may a verifier take (default: 0 (forever)))
if test "x$VERIFIER_TIMEOUT" = "x"; then VERIFIER_TIMEOUT=0 ; fi



SEARCHPATH=$srcdir/../..$PATH_SEPARATOR.$PATH_SEPARATOR../..$PATH_SEPARATOR..$PATH_SEPARATOR$PATH$PATH_SEPARATOR$HOME/bin$PATH_SEPARATOR$HOME/sbin:$HOME/local/bin:$HOME/local/sbin

AC_PATH_PROGS([NSDC], [nsd-control], [], [$SEARCHPATH])
if test "x$NSDC" = "x" ; then
    AC_MSG_ERROR([No nsd control programm (nsd-control) has been found.]) ; fi
AC_PATH_PROGS([NSDC_SETUP], [nsd-control-setup.sh nsd-control-setup], [], [$SEARCHPATH])
if test "x$NSDC_SETUP" = "x" ; then
    AC_MSG_ERROR([No nsd control programm (nsd-control-setup.sh) has been found.]) ; fi
AC_PATH_PROGS([LDNS_READ_ZONE], [ldns-read-zone], [], [$SEARCHPATH])
AC_PATH_PROGS([LDNS_KEYGEN], [ldns-keygen], [], [$SEARCHPATH])
AC_CHECK_FILE([/dev/urandom], AC_SUBST([LDNS_KEYGEN_OPTIONS], ["-r /dev/urandom"]), AC_SUBST([LDNS_KEYGEN_OPTIONS], []))
AC_PATH_PROGS([LDNS_SIGNZONE], [ldns-signzone], [], [$SEARCHPATH])
AC_PATH_PROGS([LDNS_VERIFY_ZONE], [ldns-verify-zone], [], [$SEARCHPATH])
AC_PATH_PROGS([MULTITAIL], [multitail], [], [$SEARCHPATH])
AC_PATH_PROGS([BASHELL], [bash], [], [$SEARCHPATH])

AC_ARG_VAR(VERIFIER, Verifier program to run (default: ldns-verify-zone))
if test "x$VERIFIER" = "x"
then VERIFIER="$LDNS_VERIFY_ZONE"
else if test "x$VERIFIER" = "xdebug"
     then VERIFIER="$BASHELL $srcdir/hook.sh $PROXY"
     fi
fi

if test "x$MULTITAIL" = "x" ; then
    AC_CONFIG_FILES([multitail.sh], [chmod +x multitail.sh])
    AC_SUBST([MULTITAIL],[./multitail.sh]) 
fi

AC_CONFIG_SRCDIR([Makefile.in])

ZONES=""
ZONE_FILES=""
SIGNED_ZONE_FILES=""
SIGNED_ZONE_DEPENDENCIES=""
TSIGS=""
DNSKEYS=""
VERIFIERS=""
ZONES_VERIFIERS=""
MASTER_INCLUDES=""
PROXY_INCLUDES=""
SLAVE_INCLUDES=""
MAKEFILE_LINES=""
INCR_ZONES=""
RUIN_ZONES=""
if test $NZONES -gt 1
then
	COUNT=0
	while test $COUNT -lt $NZONES
	do
		ZONE_N=`eval printf "%s" \\$ZONE$COUNT`
		if test "x$ZONE_N" = "x"
		then ZONE_N=`echo $ZONE | sed "s/\..*/-${COUNT}&/g"` ; fi
		eval ZONE$COUNT=$ZONE_N

		ZONES="$ZONES$ZONE_N "
		ZONE_FILES="$ZONE_FILES$MASTER/$ZONE_N "
		SIGNED_ZONE_FILES="$SIGNED_ZONE_FILES$MASTER/$ZONE_N.signed "
		DNSKEYS="$DNSKEYS$MASTER/$ZONE_N.private "

		for ROLE in master-notify-proxy proxy-xfr-from-master \
				proxy-notify-slave slave-xfr-from-proxy \
				slave-xfr-from-master
		do
			TSIGS="${TSIGS}tsigs/$ROLE.$ZONE_N.tsig "
		done

		VERIFIER_N=`eval printf "%s" \\$VERIFIER$COUNT`
		if test "x$VERIFIER_N" = "x"
		then VERIFIER_N="$VERIFIER"
		else if test "x$VERIFIER_N" = "xdebug"
		     then VERIFIER="$BASHELL $srcdir/hook.sh $PROXY"
		     fi
		fi

		VERIFIER_N=`echo $VERIFIER_N | sed 's/ /__@@@__/g'`
		eval VERIFIER$COUNT=$VERIFIER_N

		VERIFIERS="$VERIFIERS$VERIFIER_N "
		ZONES_VERIFIERS="$ZONES_VERIFIERS$ZONE_N:$VERIFIER_N "

		MASTER_INCLUDES="$MASTER_INCLUDES
include: \"`pwd`/${MASTER}/${MASTER}.${ZONE_N}.cf\""
		PROXY_INCLUDES="$PROXY_INCLUDES
include: \"`pwd`/${PROXY}/${PROXY}.${ZONE_N}.cf\""
		SLAVE_INCLUDES="$SLAVE_INCLUDES
include: \"`pwd`/${SLAVE}/${SLAVE}.${ZONE_N}.cf\""
		SIGNED_ZONE_DEPENDENCIES="$SIGNED_ZONE_DEPENDENCIES
$MASTER/$ZONE_N.signed: $MASTER/$ZONE_N $MASTER/$ZONE_N.private"

		INCR_ZONES="${INCR_ZONES}incr-$ZONE_N "
		RUIN_ZONES="${RUIN_ZONES}ruin-$ZONE_N "
		MAKEFILE_LINES="$MAKEFILE_LINES
incr$COUNT: incr-$ZONE_N $MASTER/$ZONE_N.signed
ruin$COUNT: incr$COUNT ruin-$ZONE_N
update-$ZONE_N: incr-$ZONE_N $MASTER/$ZONE_N.signed reload-\$(MASTER)
bad-update-$ZONE_N: incr-$ZONE_N $MASTER/$ZONE_N.signed ruin-$ZONE_N \\
		reload-\$(MASTER)
update$COUNT: update-$ZONE_N
bad-update$COUNT: bad-update-$ZONE_N"

		COUNT=`expr $COUNT + 1`
	done
else
	MASTER_INCLUDES="include: \"`pwd`/${MASTER}/${MASTER}.${ZONE}.cf\""
	PROXY_INCLUDES="include: \"`pwd`/${PROXY}/${PROXY}.${ZONE}.cf\""
	SLAVE_INCLUDES="include: \"`pwd`/${SLAVE}/${SLAVE}.${ZONE}.cf\""
	ZONES="${ZONE}"
	ZONE_FILES="${MASTER}/${ZONE}"
	SIGNED_ZONE_FILES="${MASTER}/${ZONE}.signed"
	SIGNED_ZONE_DEPENDENCIES="${MASTER}/${ZONE}.signed: ${MASTER}/${ZONE} ${MASTER}/${ZONE}.private"
	DNSKEYS="${MASTER}/${ZONE}.private"

	for ROLE in master-notify-proxy proxy-xfr-from-master \
			proxy-notify-slave slave-xfr-from-proxy \
			slave-xfr-from-master
	do
		TSIGS="${TSIGS}tsigs/$ROLE.$ZONE.tsig "
	done

	VERIFIER_N=`echo $VERIFIER | sed 's/ /__@@@__/g'`
	VERIFIERS="${VERIFIER_N}"
	ZONES_VERIFIERS="${ZONE}:${VERIFIER_N} "
	INCR_ZONES="${INCR_ZONES}incr-$ZONE "
	RUIN_ZONES="${RUIN_ZONES}ruin-$ZONE "
	MAKEFILE_LINES="$MAKEFILE_LINES
incr-zone0 incr-zone incr: incr-$ZONE ${MASTER}/${ZONE}.signed
ruin-zone0 ruin-zone ruin: incr-$ZONE ${MASTER}/${ZONE}.signed ruin-$ZONE
update-$ZONE: incr-$ZONE ${MASTER}/${ZONE}.signed reload-\$(MASTER)
bad-update-$ZONE: incr-$ZONE ${MASTER}/${ZONE}.signed ruin-$ZONE reload-\$(MASTER)
update0 update: update-$ZONE
bad-update0 bad-update: bad-update-$ZONE"
fi
if test $NZONES -gt 1
then
	MAKEFILE_LINES="$MAKEFILE_LINES
update: incr-all \$(SIGNED_ZONE_FILES) reload-\$(MASTER)
bad-update: incr-all \$(SIGNED_ZONE_FILES) ruin-all reload-\$(MASTER)"
fi
ZONES="${ZONES% }"
ZONE_FILES="${ZONE_FILES% }"
SIGNED_ZONE_FILES="${SIGNED_ZONE_FILES% }"
TSIGS="${TSIGS% }"
DNSKEYS="${DNSKEYS% }"
VERIFIERS="${VERIFIERS% }"
ZONES_VERIFIERS="${ZONES_VERIFIERS% }"
INCR_ZONES="${INCR_ZONES% }"
RUIN_ZONES="${RUIN_ZONES% }"
AC_SUBST([ZONES])
AC_SUBST([ZONE_FILES])
AC_SUBST([SIGNED_ZONE_FILES])
AC_SUBST([MASTER_INCLUDES])
AC_SUBST([PROXY_INCLUDES])
AC_SUBST([SLAVE_INCLUDES])
AC_SUBST([SIGNED_ZONE_DEPENDENCIES])
AC_SUBST([TSIGS])
AC_SUBST([DNSKEYS])
AC_SUBST([VERIFIERS])
AC_SUBST([ZONES_VERIFIERS])
AC_SUBST([INCR_ZONES])
AC_SUBST([RUIN_ZONES])
AC_SUBST([MAKEFILE_LINES])

AC_SUBST([ZONESDIR], [`pwd`])
AC_SUBST([USERNAME], [`whoami`])

AC_ARG_ENABLE(sideline, AC_HELP_STRING([--enable-sideline], 
[Slave transfers from master directly, but only serials notified by the proxy. ARG may be notify-only to not have backup transfer from the proxy.]))
case "$enable_sideline" in
	yes)
		SLAVE_TEMPLATE=sideline-slave.zone.cf.in
		;;
	notify-only)
		SLAVE_TEMPLATE=sideline-notify-only-slave.zone.cf.in
		;;
	no)
		SLAVE_TEMPLATE=slave.zone.cf.in
		;;
	*)
		SLAVE_TEMPLATE=slave.zone.cf.in
		if test "x$enable_sideline" != "x"
		then AC_MSG_ERROR([--enable-sideline option, "$enable_sideline", should be "yes", "no" or "notify-only"])
		fi
esac

CONFIG_FILES=""
if test $NZONES -gt 1
then
	COUNT=0
	ZONE="@ZONE@"
	while test $COUNT -lt $NZONES
	do
		ZONE_N=`eval printf "%s" \\$ZONE$COUNT`
		AC_CONFIG_FILES([${MASTER}/${ZONE_N}:zonefile.in])
		AC_CONFIG_FILES(
			[${MASTER}/${MASTER}.${ZONE_N}.cf:master.zone.cf.in]
		)
		AC_CONFIG_FILES(
			[${PROXY}/${PROXY}.${ZONE_N}.cf:proxy.zone.cf.in]
		)
		AC_CONFIG_FILES(
			[${SLAVE}/${SLAVE}.${ZONE_N}.cf:${SLAVE_TEMPLATE}]
		)
		CONFIG_FILES="${CONFIG_FILES}${MASTER}/${MASTER}.${ZONE_N}.cf "
		CONFIG_FILES="${CONFIG_FILES}${PROXY}/${PROXY}.${ZONE_N}.cf "
		CONFIG_FILES="${CONFIG_FILES}${SLAVE}/${SLAVE}.${ZONE_N}.cf "
		COUNT=`expr $COUNT + 1`
	done
else
	AC_CONFIG_FILES(
		[${MASTER}/${ZONE}:zonefile.in]
		[${MASTER}/${MASTER}.${ZONE}.cf:master.zone.cf.in]
		[${PROXY}/${PROXY}.${ZONE}.cf:proxy.zone.cf.in]
		[${SLAVE}/${SLAVE}.${ZONE}.cf:${SLAVE_TEMPLATE}]
	)
	CONFIG_FILES="${CONFIG_FILES}${MASTER}/${MASTER}.${ZONE}.cf "
	CONFIG_FILES="${CONFIG_FILES}${PROXY}/${PROXY}.${ZONE}.cf "
	CONFIG_FILES="${CONFIG_FILES}${SLAVE}/${SLAVE}.${ZONE}.cf "
fi

AC_CONFIG_FILES(
	[${MASTER}/${MASTER}.cf:master.server.cf.in]
	[${PROXY}/${PROXY}.cf:proxy.server.cf.in]
	[${SLAVE}/${SLAVE}.cf:slave.server.cf.in]
)

CONFIG_FILES="${CONFIG_FILES}${MASTER}/${MASTER}.cf "
CONFIG_FILES="${CONFIG_FILES}${PROXY}/${PROXY}.cf "
CONFIG_FILES="${CONFIG_FILES}${SLAVE}/${SLAVE}.cf "
CONFIG_FILES=${CONFIG_FILES% }
AC_SUBST([CONFIG_FILES])

AC_CONFIG_FILES([Makefile], [
for ZONE_VERIFIER in $ZONES_VERIFIERS
do
	ZONE=`echo ${ZONE_VERIFIER%:*} | sed 's/__@@@__/ /g'`
	VERIFIER=`echo ${ZONE_VERIFIER#*:} \
		| sed 's/__@@@__/ /g' | sed 's/\//\\\\\//g'`
	sed "s/@ZONE@/${ZONE}/g" "${MASTER}/${ZONE}" > "${MASTER}/${ZONE}.new"
	mv "${MASTER}/${ZONE}.new" "${MASTER}/${ZONE}"

	sed "s/@ZONE@/${ZONE}/g" "${MASTER}/${MASTER}.${ZONE}.cf" \
		| sed "s/@VERIFIER@/${VERIFIER}/g" \
		> "${MASTER}/${MASTER}.${ZONE}.cf.new"
	mv "${MASTER}/${MASTER}.${ZONE}.cf.new" "${MASTER}/${MASTER}.${ZONE}.cf"
	sed "s/@ZONE@/${ZONE}/g" "${PROXY}/${PROXY}.${ZONE}.cf" \
		| sed "s/@VERIFIER@/${VERIFIER}/g" \
		> "${PROXY}/${PROXY}.${ZONE}.cf.new"
       	mv "${PROXY}/${PROXY}.${ZONE}.cf.new" "${PROXY}/${PROXY}.${ZONE}.cf"

	sed "s/@ZONE@/${ZONE}/g" "${SLAVE}/${SLAVE}.${ZONE}.cf" \
		| sed "s/@VERIFIER@/${VERIFIER}/g" \
		> "${SLAVE}/${SLAVE}.${ZONE}.cf.new"
	mv "${SLAVE}/${SLAVE}.${ZONE}.cf.new" "${SLAVE}/${SLAVE}.${ZONE}.cf"
done
], [
ZONES_VERIFIERS='$ZONES_VERIFIERS'
MASTER='$MASTER'
PROXY='$PROXY'
SLAVE='$SLAVE'
])

AC_OUTPUT

cat <<SETTINGS_OVERVIEW

    Settings:
        crednsc      : $NSDC
        zones         : $ZONES
	master        : $MASTER	$MASTER_IP@$MASTER_PORT
	proxy         : $PROXY	$PROXY_IP@$PROXY_PORT
	slave         : $SLAVE	$SLAVE_IP@$SLAVE_PORT

	verifier          : $VERIFIER
	verifier-count    : $VERIFIER_COUNT
	verifier-timeout  : $VERIFIER_TIMEOUT
	verifier-feed-zone: $VERIFIER_FEED_ZONE
	verifier-ip       : $VERIFY_IP@$VERIFY_PORT

SETTINGS_OVERVIEW

case `uname` in
linux|Linux)
	plist=`netstat -n -A ip -A ip6 -a | sed -e 's/^.*:\(@<:@0-9@:>@*\) .*$/\1/'`
	;;
FreeBSD|freebsd|NetBSD|netbsd|OpenBSD|openbsd)
	plist=`netstat -n -a | grep "^@<:@ut@:>@@<:@dc@:>@p@<:@46@:>@ " | sed -e 's/^.*\.\(@<:@0-9@:>@*\) .*$/\1/'`
	;;
Solaris|SunOS|Darwin)
	plist=`netstat -n -a | sed -e 's/^.*\.\(@<:@0-9@:>@*\) .*$/\1/' | grep '^@<:@0-9@:>@*$'`
	;;
*)
	plist=""
	;;
esac

if test "x$plist" != "x"
then
	if echo "$plist" | grep "^$MASTER_PORT" >/dev/null 2>&1; then
		AC_MSG_WARN([MASTER_PORT $MASTER_PORT is already in use.])
	fi
	if echo "$plist" | grep "^$PROXY_PORT" >/dev/null 2>&1; then
		AC_MSG_WARN([PROXY_PORT $PROXY_PORT is already in use.])
	fi
	if echo "$plist" | grep "^$VERIFY_PORT" >/dev/null 2>&1; then
		AC_MSG_WARN([VERIFY_PORT $VERIFY_PORT is already in use.])
	fi
	if echo "$plist" | grep "^$SLAVE_PORT" >/dev/null 2>&1; then
		AC_MSG_WARN([SLAVE_PORT $SLAVE_PORT is already in use.])
	fi
fi

