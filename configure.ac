dnl
dnl Some global settings
dnl
AC_INIT(NSD,1.2.0,nsd-bugs@nlnetlabs.nl)
AC_CONFIG_HEADER([config.h])

dnl
dnl By default set $sysconfdir to /etc and $localstatedir to /var
dnl
case "$prefix" in
	NONE)
		case "$sysconfdir" in
			'${prefix}/etc')
				sysconfdir=/etc
			;;
                esac
		case "$localstatedir" in
			'${prefix}/var')
				localstatedir=/var
			;;
		esac
	;;
esac

#
# Determine configuration directory
#
configdir=$sysconfdir/nsd
AC_ARG_WITH([configdir],
	AC_HELP_STRING([--with-configdir=dir], [NSD configuration directory]),
	[configdir=$withval])
AC_SUBST(configdir)

#
# Determine the pidfile location. Check if /var/run exists, if so set pidfile
# to /var/run/nsd.pid by default
#
if test -d ${localstatedir}/run; then
	pidfile=${localstatedir}/run/nsd.pid
else
	pidfile=${configdir}/nsd.pid
fi
AC_ARG_WITH([pidfile],
	AC_HELP_STRING([--with-pidfile=path], [Pathname to the NSD pidfile]),
	[pidfile=$withval])
AC_SUBST(pidfile)

#
# Determine location of nsd.zones
#
zonesfile=$configdir/nsd.zones
AC_ARG_WITH([zonesfile],
	AC_HELP_STRING([--with-zonesfile=path], [Pathname to the NSD list of zones]),
	[zonesfile=$withval])
AC_SUBST(zonesfile)

#
# Determine location of nsd.db
#
dbfile=$configdir/nsd.db
AC_ARG_WITH([dbfile],
	AC_HELP_STRING([--with-dbfile=path], [Pathname to the NSD database]),
	[dbfile=$withval])
AC_SUBST(dbfile)

#
# Determine location of nsd config file
#
configfile=$configdir/nsdc.conf
AC_ARG_WITH([configfile],
	AC_HELP_STRING([--with-configfile=path], [Pathname to the NSD configuration file]),
	[configfile=$withval])
AC_SUBST(configfile)

#
# Determine the default directory for the master zone files
#
zonesdir=$configdir
AC_ARG_WITH([zonesdir],
	AC_HELP_STRING([--with-zonesdir=dir], [NSD default location for master zone files]),
	[zonesdir=$withval])
AC_SUBST(zonesdir)

#
# Determine the user name to drop privilidges to
#
user=nsd
AC_ARG_WITH([user],
	AC_HELP_STRING([--with-user=username], [User name or ID to answer the queries with]),
	[user=$withval])
AC_SUBST(user)

#
# Determine the location of namedxfer
#
AC_ARG_WITH([namedxfer],
	AC_HELP_STRING([--with-namedxfer=path], [Pathname to BIND8 named-xfer program if any]),
	[namedxfer=$withval], [namedxfer=""])
AC_SUBST(namedxfer)

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_INSTALL

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stddef.h stdlib.h string.h strings.h sys/param.h sys/socket.h syslog.h unistd.h sys/select.h stdarg.h netdb.h sys/bitypes.h dlfcn.h tcpd.h])

AC_SEARCH_LIBS(inet_addr, [nsl])
AC_SEARCH_LIBS(socket, [socket])

AC_SEARCH_LIBS(dlopen, [dl])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

dnl LIBGTOP_CHECK_TYPE
dnl Stolen from Gnome's anjuta
dnl Improved version of AC_CHECK_TYPE which takes into account
dnl that we need to #include some other header files on some
dnl systems to get some types.

dnl AC_LIBGTOP_CHECK_TYPE(TYPE, DEFAULT)
AC_DEFUN([AC_LIBGTOP_CHECK_TYPE],
[AC_REQUIRE([AC_HEADER_STDC])dnl
AC_MSG_CHECKING(for $1)
AC_CACHE_VAL(ac_cv_type_$1,
[AC_EGREP_CPP(dnl
changequote(<<,>>)dnl
<<(^|[^a-zA-Z_0-9])$1[^a-zA-Z_0-9]>>dnl
changequote([,]), [#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif

/* For Tru64 */
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
], ac_cv_type_$1=yes, ac_cv_type_$1=no)])dnl
AC_MSG_RESULT($ac_cv_type_$1)
if test $ac_cv_type_$1 = no; then
  AC_DEFINE($1, $2, Define "$1" to "$2" if "$1" is missing)
fi
])

AC_LIBGTOP_CHECK_TYPE(u_char, unsigned char)
AC_LIBGTOP_CHECK_TYPE(u_long, unsigned long)  
AC_LIBGTOP_CHECK_TYPE(int8_t, char) 
AC_LIBGTOP_CHECK_TYPE(int16_t, short)
AC_LIBGTOP_CHECK_TYPE(int32_t, int)
AC_LIBGTOP_CHECK_TYPE(u_int8_t, unsigned char)
AC_LIBGTOP_CHECK_TYPE(u_int16_t, unsigned short)
AC_LIBGTOP_CHECK_TYPE(u_int32_t, unsigned int)
AC_LIBGTOP_CHECK_TYPE(socklen_t, int)
AC_LIBGTOP_CHECK_TYPE(sockaddr_storage, sockaddr_in)

AC_CHECK_TYPE(in_addr_t, [], [AC_DEFINE([in_addr_t], [u_int32_t], [in_addr_t])], [
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif])

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([alarm dup2 endpwent gethostname inet_aton memset memcpy select socket strcasecmp strchr strdup strerror strncasecmp strtol getaddrinfo getnameinfo freeaddrinfo gai_strerror sigaction sigprocmask dlopen dlerror dlsym dlclose])

#
# Checking for missing functions we can replace
#
AC_REPLACE_FUNCS(basename)
AC_REPLACE_FUNCS(inet_pton)
AC_REPLACE_FUNCS(snprintf)
AC_REPLACE_FUNCS(b64_pton)
AC_REPLACE_FUNCS(b64_ntop)
AC_REPLACE_FUNCS(timegm)

dnl
dnl Check for libwrap
dnl
AC_ARG_WITH(libwrap,
	AC_HELP_STRING([--with-libwrap=[pathname]],
		[Compile in libwrap (tcp_wrappers) support.]), [], [withval="yes"])

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
AC_DEFINE_UNQUOTED([IDENTITY], ["unindentified server"], [Define to the default nsd identity.])
AC_DEFINE_UNQUOTED([VERSION], [PACKAGE_STRING], [Define to the NSD version to answer version.server query.])
AC_DEFINE_UNQUOTED([TCP_BACKLOG], [5], [Define to the backlog to be used with listen.])
AC_DEFINE_UNQUOTED([TCP_PORT], ["53"], [Define to the default tcp port.])
AC_DEFINE_UNQUOTED([TCP_MAX_MESSAGE_LEN], [16384], [Define to the default maxium message length.])
AC_DEFINE_UNQUOTED([TCP_TIMEOUT], [120], [Define to the default tcp timeout.])
AC_DEFINE_UNQUOTED([UDP_PORT], ["53"], [Define to the default udp port.])
AC_DEFINE_UNQUOTED([UDP_MAX_MESSAGE_LEN], [512], [Define to the default maximum udp message length.])
AC_DEFINE_UNQUOTED([EDNS_MAX_MESSAGE_LEN], [4096], [Define to the default maximum message length with EDNS.])
AC_DEFINE_UNQUOTED([MAX_INTERFACES], [8], [Define to the maximum interfaces to serve.])
AC_DEFINE_UNQUOTED([FACILITY], [LOG_DAEMON], [Define to the default facility for syslog.])
AC_DEFINE_UNQUOTED([MAXSYSLOGMSGLEN], [512], [Define to the maximum message length to pass to syslog.])
AC_DEFINE_UNQUOTED([AXFR_DAEMON], ["axfr"], [Define to the default daemon name to check for axfr.])
AC_DEFINE_UNQUOTED([AXFR_DAEMON_PREFIX], ["axfr-"], [Define to the default daemon prefix to check for axfr.])

dnl
dnl Features
dnl
AC_ARG_ENABLE(root-server, AC_HELP_STRING([--enable-root-server], [Configure NSD as a root server]))
case "$enable_root_server" in
        yes)
		AC_DEFINE_UNQUOTED([ROOT_SERVER], [], [Define this to configure as a root server.])
		;;
        no|*)
                ;;
esac

AC_ARG_ENABLE(ipv6, AC_HELP_STRING([--enable-ipv6], [Enables IPv6 support]))
case "$enable_ipv6" in
        no|'')
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
	yes|'')
		AC_DEFINE_UNQUOTED([BIND8_STATS], [], [Define this to enable BIND8 like NSTATS & XSTATS.])
		;;
	no|*)
		;;
esac

AC_ARG_ENABLE(plugins, AC_HELP_STRING([--enable-plugins], [Enable plugin support]))
case "$enable_plugins" in
        yes)
		AC_DEFINE([PLUGINS], [], [Define this to enable plugin support.])
		;;
        no|*)
                ;;
esac

AC_ARG_ENABLE(checking, AC_HELP_STRING([--enable-checking], [Enable internal runtime checks]))
case "$enable_checking" in
        yes)
		;;
        no|*)
                AC_DEFINE([NDEBUG], [], [Undefine this to enable internal runtime checks.])
                ;;
esac

AH_BOTTOM([
#include <sys/types.h>
])

AH_BOTTOM([
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
