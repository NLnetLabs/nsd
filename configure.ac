dnl
dnl Some global settings
dnl
AC_INIT(NSD,2.2.0,nsd-bugs@nlnetlabs.nl)
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
AC_PROG_LEX
AC_PROG_YACC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T

AC_DEFUN([AC_CHECK_FORMAT_ATTRIBUTE],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(whether the C compiler (${CC-cc}) accepts the "format" attribute)
AC_CACHE_VAL(ac_cv_c_format_attribute,
[ac_cv_c_format_attribute=no
AC_TRY_COMPILE(
[#include <stdio.h>
void f (char *format, ...) __attribute__ ((format (printf, 1, 2)));
void (*pf) (char *format, ...) __attribute__ ((format (printf, 1, 2)));
], [
   f ("%s", "str");
],
[ac_cv_c_format_attribute="yes"],
[ac_cv_c_format_attribute="no"])
])

AC_MSG_RESULT($ac_cv_c_format_attribute)
if test $ac_cv_c_format_attribute = yes; then
  AC_DEFINE(HAVE_ATTR_FORMAT, 1, [Whether the C compiler accepts the "format" attribute])
fi
])dnl

AC_DEFUN([AC_CHECK_UNUSED_ATTRIBUTE],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(whether the C compiler (${CC-cc}) accepts the "unused" attribute)
AC_CACHE_VAL(ac_cv_c_unused_attribute,
[ac_cv_c_unused_attribute=no
AC_TRY_COMPILE(
[#include <stdio.h>
void f (char *u __attribute__((unused)));
], [
   f ("x");
],
[ac_cv_c_unused_attribute="yes"],
[ac_cv_c_unused_attribute="no"])
])

AC_MSG_RESULT($ac_cv_c_unused_attribute)
if test $ac_cv_c_unused_attribute = yes; then
  AC_DEFINE(HAVE_ATTR_UNUSED, 1, [Whether the C compiler accepts the "unused" attribute])
fi
])dnl

AC_CHECK_FORMAT_ATTRIBUTE
AC_CHECK_UNUSED_ATTRIBUTE

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h signal.h strings.h fcntl.h limits.h netinet/in.h stddef.h sys/param.h sys/socket.h syslog.h unistd.h sys/select.h stdarg.h stdint.h netdb.h sys/bitypes.h dlfcn.h tcpd.h openssl/hmac.h])

AC_SEARCH_LIBS(inet_pton, [nsl])
AC_SEARCH_LIBS(socket, [socket])

AC_SEARCH_LIBS(dlopen, [dl])

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
changequote([,]), [
#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
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

AC_LIBGTOP_CHECK_TYPE(int8_t, char) 
AC_LIBGTOP_CHECK_TYPE(int16_t, short)
AC_LIBGTOP_CHECK_TYPE(int32_t, int)
AC_LIBGTOP_CHECK_TYPE(uint8_t, unsigned char)
AC_LIBGTOP_CHECK_TYPE(uint16_t, unsigned short)
AC_LIBGTOP_CHECK_TYPE(uint32_t, unsigned int)
AC_LIBGTOP_CHECK_TYPE(socklen_t, int)
AC_LIBGTOP_CHECK_TYPE(sig_atomic_t, int)

AC_CHECK_TYPE(in_addr_t, [], [AC_DEFINE([in_addr_t], [uint32_t], [in_addr_t])], [
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
AC_CHECK_FUNCS([alarm chroot dup2 endpwent gethostname memset memcpy mmap socket strcasecmp strchr strdup strerror strncasecmp strtol getaddrinfo getnameinfo freeaddrinfo gai_strerror sigaction sigprocmask dlopen dlerror dlsym dlclose])

#
# Checking for missing functions we can replace
#
AC_REPLACE_FUNCS(basename)
AC_REPLACE_FUNCS(inet_pton)
AC_REPLACE_FUNCS(snprintf)
AC_REPLACE_FUNCS(b64_pton)
AC_REPLACE_FUNCS(b64_ntop)
AC_REPLACE_FUNCS(timegm)
AC_REPLACE_FUNCS(pselect)

dnl dnl Check for libwrap.  Note that libwrap requires 
dnl yp_get_default_domain on Linux but that normally the required nsl 
dnl library isn't linked in (and no error occurs when dynamically linking)
AC_ARG_WITH(libwrap,
	AC_HELP_STRING([--with-libwrap=[pathname]],
		[Compile in libwrap (tcp_wrappers) support.]), [], [withval="yes"])

case "$withval" in
	no|'')
		;;
	yes)
		AC_CHECK_LIB(wrap, request_init, [
			AC_DEFINE_UNQUOTED([LIBWRAP], [], [Define to use hosts_access() from -lwrap.])
			LIBWRAP="-lwrap"
                        AC_SEARCH_LIBS(yp_get_default_domain, [nsl])
                        ])
		;;
	*)
		LIBWRAP="-L$withval -lwrap"
		OLDLIBS="$LIBS"
		LIBS="$LIBWRAP $LIBS"
		AC_TRY_LINK([ int allow_severity; int deny_severity; ],
			[ hosts_access(); ],
			[AC_DEFINE_UNQUOTED([LIBWRAP], [], [Define to use hosts_access() from -lwrap.])
                         AC_SEARCH_LIBS(yp_get_default_domain, [nsl])
                        ],
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
dnl AC_DEFINE_UNQUOTED([FACILITY], [LOG_DAEMON], [Define to the default facility for syslog.])
AC_DEFINE_UNQUOTED([MAXSYSLOGMSGLEN], [512], [Define to the maximum message length to pass to syslog.])
AC_DEFINE_UNQUOTED([AXFR_DAEMON], ["axfr"], [Define to the default daemon name to check for axfr.])
AC_DEFINE_UNQUOTED([AXFR_DAEMON_PREFIX], ["axfr-"], [Define to the default daemon prefix to check for axfr.])

dnl
dnl Determine the syslog facility to use
dnl
facility=LOG_DAEMON
AC_ARG_WITH([facility],
        AC_HELP_STRING([--with-facility=name], [Syslog default facility (LOG_DAEMON)]),
        [facility=$withval])
AC_DEFINE_UNQUOTED([FACILITY], $facility, [Define to the default facility for syslog.])

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

AC_ARG_ENABLE(ipv6, AC_HELP_STRING([--disable-ipv6], [Disables IPv6 support]))
case "$enable_ipv6" in
        no)
                ;;
        yes|*)
		AC_DEFINE_UNQUOTED([INET6], [], [Define this to enable IPv6 support.])
		;;
esac

AC_ARG_ENABLE(dnssec, AC_HELP_STRING([--enable-dnssec], [Enable experimental DNSSEC support according to the latest drafts.]))
case "$enable_dnssec" in
        yes)
		AC_DEFINE_UNQUOTED([DNSSEC], [], [Define this enable experimental DNSSEC support.])
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

AC_ARG_ENABLE(tsig, AC_HELP_STRING([--enable-tsig], [Enable TSIG support]))
case "$enable_tsig" in
        yes)
                AC_CHECK_LIB(crypto, HMAC_CTX_init,, [AC_MSG_ERROR(TSIG requires OpenSSL crypto libraries.)])
                AC_DEFINE([TSIG], [], [Define this to enable TSIG support.])
		;;
        no|*)
                ;;
esac

AC_ARG_ENABLE(mmap, AC_HELP_STRING([--enable-mmap], [Configure NSD to load the database using mmap(2).]))
case "$enable_mmap" in
        yes)
                if test "$ac_cv_func_mmap" != yes; then
                    AC_MSG_ERROR(mmap support requested but mmap not found)
                fi
		AC_DEFINE_UNQUOTED([USE_MMAP], [], [Define this to load the database using mmap(2).])
		;;
        no|*)
                ;;
esac

AH_BOTTOM([
#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

/* For Tru64 */
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
])

AH_BOTTOM([
#ifdef HAVE_ATTR_FORMAT
#define ATTR_FORMAT(archetype, string_index, first_to_check) \
    __attribute__ ((format (archetype, string_index, first_to_check)))
#else /* !HAVE_ATTR_FORMAT */
#define ATTR_FORMAT(archetype, string_index, first_to_check) /* empty */
#endif /* !HAVE_ATTR_FORMAT */
#ifdef HAVE_ATTR_UNUSED
#define ATTR_UNUSED __attribute__((unused))
#else /* !HAVE_ATTR_UNUSED */
#define ATTR_UNUSED /* empty */
#endif /* !HAVE_ATTR_UNUSED */
])

AH_BOTTOM([
#ifndef IPV6_MIN_MTU
#define IPV6_MIN_MTU 1280
#endif /* IPV6_MIN_MTU */

#ifndef AF_INET6
#define AF_INET6	28
#endif /* AF_INET6 */
])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
