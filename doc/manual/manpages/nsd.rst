nsd(8)
======

Synopsis
--------

:command:`nsd` [:option:`-4`] [:option:`-6`] [:option:`-a`
``ip-address[@port]``] [:option:`-c` ``configfile``] [:option:`-d`]
[:option:`-f` ``database``] [:option:`-h`] [:option:`-i` ``identity``]
[:option:`-I` ``nsid``] [:option:`-l` ``logfile``] [:option:`-N`
``server-count``] [:option:`-n` ``noncurrent-tcp-count``]  [:option:`-P`
``pidfile``] [:option:`-p` ``port``] [:option:`-s` ``seconds``] [:option:`-t`
``chrootdir``] [:option:`-u` ``username``] [:option:`-V` ``level``]
[:option:`-v`]

Description
-----------

:command:`NSD` is a complete implementation of an  authoritative DNS nameserver.
Upon startup, :command:`NSD` will read the database specified with :option:`-f`
``database`` argument and put itself into background and answers queries on port
53 or a different port specified with :option:`-p` ``port`` option. The database
is created if it does not exist. By default, :command:`NSD` will bind to all
local interfaces available. Use the :option:`-a` ``ip-address[@port]`` option to
specify a single particular interface address to be bound. If this  option is
given more than once, :command:`NSD` will bind its UDP and TCP sockets to all
the specified ip-addresses separately. If IPv6 is enabled when :command:`NSD` is
compiled an IPv6 address can also be specified.

Options
-------

All the options can be specified in the configfile (:option:`-c` argument),
except for the :option:`-v` and :option:`-h` options. If options are specified
on the commandline,  the options on the commandline take precedence over the
options in the configfile.

Normally :command:`NSD` should be started with the :manpage:`nsd-control(8)`
``start`` command invoked from a :file:`/etc/rc.d/nsd.sh` script or similar at
the operating system startup.

.. option:: -4

      Only listen to IPv4 connections.

.. option:: -6

      Only listen to IPv6 connections.

.. option:: -a ip-address[@port]

      Listen to the specified  ip-address. The ip-address must be specified in
      numeric format (using the standard IPv4 or IPv6 notation). Optionally, a
      port number can be given. This flag can be specified multiple times to
      listen to multiple IP addresses. If this flag is not specified,
      :command:`NSD` listens to the wildcard interface.

.. option:: -c configfile

      Read specified *configfile* instead of the default
      :file:`/etc/nsd/nsd.conf`. For format description see
      :manpage:`nsd.conf(5)`.

.. option:: -d

      Do not fork, stay in the foreground.

.. option:: -f database

      Use the specified *database* instead of the default of
      :file:`/var/db/nsd/nsd.db`. If a ``zonesdir:`` is specified in the config
      file this path can be relative to that directory.

.. option:: -h

      Print help information and exit.

.. option:: -i identity

      Return the specified *identity* when asked for *CH TXT ID.SERVER* (This
      option is used to determine which server is answering the queries when
      they are anycast). The default is the name returned by gethostname(3).

.. option:: -I nsid

      Add the specified  *nsid* to the EDNS section of the answer when queried
      with an NSID EDNS enabled packet. As a sequence of hex characters or
      with ascii\_ prefix and then an ascii string.

.. option:: -l logfile

      Log messages to the specified logfile. The default is to log to stderr and
      syslog. If a ``zonesdir:`` is specified in the config file this path can
      be relative to that directory.

.. option:: -N count

      Start count :command:`NSD` servers. The default is 1. Starting more than
      a single server is only useful on machines with multiple CPUs and/or
      network adapters.

.. option:: -n number

      The maximum number of concurrent TCP connection that can be handled by
      each server. The default is 100.

.. option:: -P pidfile

      Use the specified *pidfile* instead of the platform specific default,
      which is mostly :file:`/var/run/nsd.pid`. If a ``zonesdir:`` is specified
      in the config file, this path can be relative to that directory.

.. option:: -p port

      Answer the queries on the specified *port*. Normally this is port 53.

.. option:: -s seconds

      Produce statistics dump every *seconds* seconds. This is equal to sending
      *SIGUSR1* to the daemon periodically.

.. option:: -t chroot

      Specifies a directory to *chroot* to upon startup. This option requires
      you to ensure that appropriate  *syslogd(8)* socket (e.g. *chrootdir*
      /dev/log)  is  available, otherwise :command:`NSD` won't produce any log
      output.

.. option:: -u username

      Drop user and group privileges to those of *username* after  binding the
      socket. The *username* must be one of: username, id, or id.gid. For
      example: nsd, 80, or 80.80.

.. option:: -V level

      This value specifies the verbosity level for (non-debug) logging. Default
      is 0.

.. option:: -v

      Print the version number of :command:`NSD` to standard error and exit.

:command:`NSD` reacts to the following signals:

SIGTERM
      Stop answering queries, shutdown, and exit normally.

SIGHUP Reload.
      Scans zone files and if changed (mtime) reads them in. Also reopens the
      logfile (assists logrotation).

SIGUSR1
      Dump BIND8-style statistics into the log. Ignored otherwise.

Files
-----

/var/db/nsd/nsd.db
      default :command:`NSD` database

/var/run/nsd.pid
      the process id of the name server.

/etc/nsd/nsd.conf
      default :command:`NSD` configuration file

Diagnostics
-----------

:command:`NSD` will log all the problems via the standard *syslog(8)* daemon facility,
unless the :option:`-d` option is specified.

See Also
--------

:manpage:`nsd.conf(5)`, :manpage:`nsd-checkconf(8)`, :manpage:`nsd-control(8)`