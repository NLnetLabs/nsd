dnl
dnl Some global settings
dnl
AC_INIT(NSD,1.1a,nsd-bugs@nlnetlabs.nl)
AC_CONFIG_HEADER([config.h])

CFLAGS="-Wall -Wstrict-prototypes -Wmissing-prototypes -Wshadow -Wconversion"

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_INSTALL

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stddef.h stdlib.h string.h strings.h sys/param.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([alarm bzero dup2 endpwent gethostname inet_ntoa memset munmap select socket strcasecmp strchr strdup strerror strncasecmp strtol])

AC_CHECK_FUNCS(basename, [], [COMPAT_O="$COMPAT_O basename.o"])
AC_CHECK_FUNCS(inet_pton, [], [COMPAT_O="$COMPAT_O inet_pton.o"])
AC_SUBST(COMPAT_O)

dnl
dnl A number if --with arguements
dnl

AC_ARG_WITH(nsd-home,
	AC_HELP_STRING([--with-nsd-home=directory],
		[NSD ``home'' directory]),
	[nsdhome="$withval"],
	[nsdhome="$sysconfdir/nsd"])
AC_SUBST(nsdhome)

AC_ARG_WITH(nsd-zones,
	AC_HELP_STRING([--with-nsd-zones=filename],
		[The file containing the list of the zones to be served]),
	[nsdzones="$withval"], [nsdzones="$nsdhome/nsd.zones"])
AC_SUBST(nsdzones)

AC_ARG_WITH(nsd-db,
	AC_HELP_STRING([--nsd-db=filename],
	[The NSD run-time database (default $nsdzonesdir/nsd.db)]),
		[nsddb="$withval"], [nsddb="$nsdhome/nsd.db"])
AC_SUBST(nsddb)

AC_ARG_WITH(nsdc-conf, AC_HELP_STRING([--nsdc-conf=filename],
	[Optional configuration file for nsdc.sh]),
		[nsdcconf="$withval"], [nsdcconf="$nsdhome/nsdc.conf"])
AC_SUBST(nsdcconf)

AC_ARG_WITH(nsd-pidfile,
	AC_HELP_STRING([--nsd-pidfile=filename],
	[The file pid file of the nsd (default $nsdhome/nsd.pid)]),
		[nsdpidfile="$withval"], [nsdpidfile="$nsdhome/nsd.pid"])
AC_SUBST(nsdpidfile)

AC_ARG_WITH(nsd-user,
	AC_HELP_STRING([--with-nsd-user=user],
		[The username for nsd to setuid to before answering queries]),
	[nsduser="$withval"], [nsduser="nsd"])
AC_SUBST(nsduser)

AC_ARG_WITH(named-xfer,
	AC_HELP_STRING([--with-named-xfer=pathname],
		[Pathname to named-xfer program from bind distribution]),
	[namedxfer="$withval"])
AC_SUBST(namedxfer)

dnl
dnl Check for libwrap
dnl
AC_ARG_WITH(libwrap,
	AC_HELP_STRING([--with-libwrap=[pathname]],
		[Compile in libwrap (tcp_wrappers) support.]))

case "$withval" in
	no|'')
		;;
	yes)
		AC_CHECK_LIB(wrap, request_init, [
			AC_DEFINE_UNQUOTED([LIBWRAP], [], [Define to use hosts_access() from -lwrap.])
			LIBWRAP="-lwrap" ])
		;;
	*)
		LIBWRAP="-L$withval -lwrap"
		OLDLIBS="$LIBS"
		LIBS="$LIBWRAP $LIBS"
		AC_TRY_LINK([ int allow_severity; int deny_severity; ],
			[ hosts_access(); ],
			[AC_DEFINE_UNQUOTED([LIBWRAP], [], [Define to use hosts_access() from -lwrap.])],
			[ AC_MSG_ERROR(Could not find the $withval library.  You must first install tcp_wrappers.) ])
		LIBS="$OLDLIBS"
		;;
esac
AC_SUBST(LIBWRAP)


dnl
dnl Some random defines's
dnl
AC_DEFINE_UNQUOTED([CF_IDENTITY], ["unindentified server"], [Define to the default nsd identity.])
AC_DEFINE_UNQUOTED([CF_VERSION], [PACKAGE_STRING], [Define to the NSD version to answer version.server query.])
AC_DEFINE_UNQUOTED([CF_TCP_BACKLOG], [5], [Define to the backlog to be used with listen.])
AC_DEFINE_UNQUOTED([CF_TCP_MAX_CONNECTIONS], [8], [Define to the default maximum simultaneous tcp connections.])
AC_DEFINE_UNQUOTED([CF_TCP_PORT], [53], [Define to the default tcp port.])
AC_DEFINE_UNQUOTED([CF_TCP_MAX_MESSAGE_LEN], [16384], [Define to the default maxium message length.])
AC_DEFINE_UNQUOTED([CF_TCP_TIMEOUT], [120], [Define to the default tcp timeout.])
AC_DEFINE_UNQUOTED([CF_UDP_PORT], [53], [Define to the default udp port.])
AC_DEFINE_UNQUOTED([CF_UDP_MAX_MESSAGE_LEN], [512], [Define to the default maximum udp message length.])
AC_DEFINE_UNQUOTED([CF_EDNS_MAX_MESSAGE_LEN], [4096], [Define to the default maximum message length with EDNS.])
AC_DEFINE_UNQUOTED([CF_MAX_INTERFACES], [8], [Define to the maximum interfaces to serve.])
AC_DEFINE_UNQUOTED([CF_FACILITY], [LOG_DAEMON], [Define to the default facility for syslog.])
AC_DEFINE_UNQUOTED([MAXSYSLOGMSGLEN], [512], [Define to the maximum message length to pass to syslog.])
AC_DEFINE_UNQUOTED([AXFR_DAEMON], ["axfr"], [Define to the default daemon name to check for axfr.])
AC_DEFINE_UNQUOTED([AXFR_DAEMON_PREFIX], ["axfr-"], [Define to the default daemon prefix to check for axfr.])

dnl
dnl Features, that we always define, need to be changed permantently in the source.
dnl
AC_DEFINE_UNQUOTED([USE_HEAP_RBTREE], [], [Define to use red-black tree methods.])
AC_DEFINE_UNQUOTED([LOG_NOTIFIES], [], [Define to log incoming notifies with syslog.])

dnl
dnl Features
dnl
AC_ARG_ENABLE(ipv6, AC_HELP_STRING([--enable-ipv6], [Enables IPv6 support]))
case "$enable_ipv6" in
        no)
                ;;
        yes|*)
		AC_DEFINE_UNQUOTED([INET6], [], [Define this to enable IPv6 support.])
		;;
esac

AC_ARG_ENABLE(dnssec, AC_HELP_STRING([--enable-dnssec], [Enables DNSSEC support (experimental)]))
case "$enable_dnssec" in
	yes)
		AC_DEFINE_UNQUOTED([DNSSEC], [], [Define this to enable DNSSEC support.])
		;;
	no|*)
		;;
esac

AC_ARG_ENABLE(axfr, AC_HELP_STRING([--disable-axfr], [Disables AXFR]))

case "$enable_axfr" in
	no)
		AC_DEFINE_UNQUOTED([DISABLE_AXFR], [], [Define this to disable axfr.])
		;;
	yes|*)
		;;
esac

AC_ARG_ENABLE(bind8-stats, AC_HELP_STRING([--enable-bind8-stats], [Enables BIND8 like NSTATS & XSTATS]))

case "$enable_bind8_stats" in
	yes)
		AC_DEFINE_UNQUOTED([BIND8_STATS], [], [Define this to enable BIND8 like NSTATS & XSTATS.])
		;;
	no|*)
		;;
esac


AC_CONFIG_FILES([Makefile nsdc.sh nsdc.conf.sample])
AC_OUTPUT
