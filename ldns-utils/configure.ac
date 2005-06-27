#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(NSD,2.3-devel,nsd-bugs@nlnetlabs.nl)
AC_CONFIG_SRCDIR([../config.h])
AC_CONFIG_HEADER([config.h])

AC_AIX
# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET

# Checks for libraries.
# Checks for header files.
#AC_HEADER_STDC
#AC_HEADER_SYS_WAIT
# do the very minimum - we can always extend this
AC_CHECK_HEADERS([getopt.h stdlib.h stdio.h assert.h netinet/in.hctype.h])
AC_CHECK_HEADERS(sys/param.h sys/mount.h,,,
[
  [
   #if HAVE_SYS_PARAM_H
   # include <sys/param.h>
   #endif
  ]
])

AC_PATH_PROG(LIBXML2_CONFIG, xml2-config, [no])
if test $LIBXML2_CONFIG = no; then
   AC_MSG_ERROR([libxml2 is required, please ensure it is installed and xml2-config is in the PATH])
fi

AC_SUBST(LIBXML2_CFLAGS, [`$LIBXML2_CONFIG --cflags`])
AC_SUBST(LIBXML2_LIBS, [`$LIBXML2_CONFIG --libs`])

# ripped from http://autoconf-archive.cryp.to/check_ssl.html
# check for ldns
AC_ARG_WITH(ldns, AC_HELP_STRING([--with-ldns=pathname],[]))
AC_MSG_CHECKING(for ldns/dns.h)
for dir in $withval /usr/local/ldns /usr/lib/ldns /usr/ldns /usr/pkg /usr/local /usr; do
ldnsdir="$dir"
if test -f "$dir/include/ldns/dns.h"; then
    found_ldns="yes";
    CFLAGS="$CFLAGS -I$ldnsdir/include/ -DHAVE_LDNS";
    CXXFLAGS="$CXXFLAGS -I$ldnsdir/include/ -DHAVE_LDNS";
    break;
fi
if test -f "$dir/ldns/dns.h"; then
    found_ldns="yes";
    CFLAGS="$CFLAGS -I$ldnsdir/ -DHAVE_LDNS";
    CXXFLAGS="$CXXFLAGS -I$ldnsdir/ -DHAVE_LDNS";
    break
fi
done
if test x_$found_ldns != x_yes; then
        AC_MSG_RESULT(no)
	AC_MSG_ERROR(Cannot find ldns libraries)
else
	LIBS="$LIBS -lldns";
	LDFLAGS="$LDFLAGS -L$ldnsdir/lib";
	LDFLAGS="$LDFLAGS -L$ldnsdir/.libs"; # hack for dev.
	HAVE_LDNS=yes
        AC_MSG_RESULT(yes)
fi
AC_SUBST(HAVE_LDNS)

#
# Determine location of nsd config file
#
configfile=$configdir/nsd.conf
AC_ARG_WITH([configfile],
        AC_HELP_STRING([--with-configfile=path], [Pathname to the NSD configuration file]),
        [configfile=$withval])
AC_SUBST(configfile)



# some other stuff
# Checks for typedefs, structures, and compiler characteristics.
#AC_TYPE_UID_T
#AC_TYPE_MODE_T
#AC_TYPE_OFF_T
#AC_TYPE_SIZE_T
#AC_STRUCT_TM

# Checks for library functions.
# check for ldns
#AC_FUNC_CHOWN
#AC_FUNC_FORK
#AC_FUNC_MALLOC
#AC_FUNC_MKTIME
#AC_FUNC_STAT
#AC_CHECK_FUNCS([mkdir rmdir strchr strrchr strstr])

#AC_DEFINE_UNQUOTED(SYSCONFDIR, "$sysconfdir")

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
