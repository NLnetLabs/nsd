nsd.conf(5)
===========

Synopsis
--------

:command:`nsd.conf`

Description
-----------

:command:`Nsd.conf` is used to configure :manpage:`nsd(8)`. The file format has
attributes and values. Some attributes have attributes inside them. The notation
is: ``attribute: value``.

Comments start with ``#`` and last to the end of line. Empty lines are ignored
as is whitespace at the beginning of a line. Quotes can be used,
for names with spaces, eg. "file name.zone".

:command:`Nsd.conf` specifies options for the nsd server, zone files, primaries
and secondaries.

Example
-------

An example of a short nsd.conf file is below.

.. code-block:: text

        # Example.com nsd.conf file
        # This is a comment.

        server:
                server-count: 1 # use this number of cpu cores
                database: ""  # or use "/var/db/nsd/nsd.db"
                zonelistfile: "/var/db/nsd/zone.list"
                username: nsd
                logfile: "/var/log/nsd.log"
                pidfile: "/var/run/nsd.pid"
                xfrdfile: "/var/db/nsd/xfrd.state"

        zone:
                name: example.com
                zonefile: /etc/nsd/example.com.zone

        zone:
                # this server is master, 192.0.2.1 is the secondary.
                name: masterzone.com
                zonefile: /etc/nsd/masterzone.com.zone
                notify: 192.0.2.1 NOKEY
                provide-xfr: 192.0.2.1 NOKEY

        zone:
                # this server is secondary, 192.0.2.2 is master.
                name: secondzone.com
                zonefile: /etc/nsd/secondzone.com.zone
                allow-notify: 192.0.2.2 NOKEY
                request-xfr: 192.0.2.2 NOKEY

Then, use ``kill -HUP`` to reload changes from master zone files. And use ``kill
-TERM`` to stop the server.

File Format
-----------

There  must be whitespace between keywords. Attribute keywords end with a colon
``':'``. An attribute is followed by its containing attributes, or a value.

At the top  level only **server:**, **key:**, **pattern:**, **zone:**,
**tls-auth:**, and **remote-control:** are allowed. These are followed by their
attributes or a new top-level keyword. The **zone:** attribute is followed by
zone options. The **server:** attribute is followed by global options for the
NSD server. A **key:** attribute is used to define keys for authentication. The
**pattern:** attribute is followed by the zone options for zones  that use the
pattern. A **tls-auth:** attribute is used to define credentials for
authenticating an outgoing TLS connection used for XFR-over-TLS.

Files can be included using the **include:** directive. It can appear anywhere,
and takes a single filename as an argument. Processing continues as if the text
from the included file was copied into the config file at that point. If a
chroot is used an absolute filename is needed (with the chroot prepended), so
that the include can be  parsed  before and after application of the chroot (and
the knowledge of what that chroot is).  You can use ``'*'`` to include a
wildcard match of files,  e.g. :file:`foo/nsd.d/*.conf`. Also  ``'?'``,
``'{}'``, ``'[]'``, and ``'~'`` work, see *glob(7)*. If no files match the
pattern, this is not an error.

Server Options
^^^^^^^^^^^^^^

The global options (if not overridden from  the  NSD  commandline) are
taken from the **server:** clause. There may only be one **server:** clause.

ip-address: <ip4 or ip6>[@port] [servers] [bindtodevice] [setfib]
        NSD  will  bind  to the listed ip-address. Can be given multiple times
        to bind multiple ip-addresses. Optionally, a port number can be given.
        If none are given NSD listens to the wildcard interface. Same as
        commandline option :option:`-a`.

        To limit which NSD server(s)  listen  on  the  given  interface, specify
        one or more  servers separated by whitespace after <ip>[@port].
        Ranges can be used as a shorthand to specify multiple consecutive
        servers. By default every server will listen.

        If an interface name is used instead of ip4 or ip6, the list of IP
        addresses associated with that interface is picked up and used at server
        start.

        For servers with multiple IP addresses that can be used to send traffic
        to the internet, list them one by one, or the source address of replies
        could be wrong. This is because if the udp socket associates a source
        address of ``0.0.0.0`` then the kernel picks an ip-address with which to
        send to the internet, and it picks the wrong one. Typically needed for
        anycast instances. Use ip-transparent to be able to list addresses that
        turn on later (typical for certain load-balancing).

interface: <ip4 or ip6>[@port] [servers] [bindtodevice] [setfib]
        Same as ip-address (for ease of compatibility with unbound.conf).

ip-transparent: <yes or no>
        Allows NSD to bind to non local addresses. This is useful to have NSD
        listen to IP addresses that are not (yet) added to the network
        interface, so that it can answer immediately when the address is added.
        Default is no.

ip-freebind: <yes or no>
        Set the IP_FREEBIND option to bind to nonlocal addresses and interfaces
        that are down. Similar to ip-transparent. Default is no.

reuseport: <yes or no>
        Use the SO_REUSEPORT socket option, and create file descriptors for
        every server in the server-count. This improves performance of the
        network stack. Only really useful if you also configure a server-count
        higher than 1 (such as, equal to the number of cpus). The default is no.
        It works on Linux, but does not work on FreeBSD, and likely does not
        work on other systems.

send-buffer-size: <number>
        Set the send buffer size for query-servicing sockets. Set to 0 to use
        the default settings.

receive-buffer-size: <number>
        Set the receive buffer size for query-servicing sockets. Set to 0 to use
        the default settings.

debug-mode: <yes or no>
        Turns on debugging mode for nsd, does not fork a daemon process. Default
        is no. Same as commandline option :option:`-d`. If set to yes it does
        not fork and stays in the foreground, which can be helpful for
        commandline debugging, but is also used by certain server supervisor
        processes to ascertain that the server is running.

do-ip4: <yes or no>
        If yes, NSD listens to IPv4 connections. Default yes.

do-ip6: <yes or no>
        If yes, NSD listens to IPv6 connections. Default yes.

database: <filename>
        By default '/var/db/nsd/nsd.db' is used. The specified file is used to
        store the compiled zone information. Same as commandline option
        :option:`-f`. If set to ``""`` then no database is used. This uses less
        memory but zone updates are not (immediately) spooled to disk.

zonelistfile: <filename>
        By default :file:`/var/db/nsd/zone.list` is used. The specified file is
        used to store the dynamically added list of zones. The list is written
        to by NSD to add and delete zones. It is a text file with a zone-name
        and pattern-name on each line. This file is used for the nsd-control
        addzone and delzone commands.

identity: <string>
        Returns the specified identity when asked for ``CH TXT ID.SERVER``.
        Default is the name as returned by *gethostname(3)*. Same as commandline
        option :option:`-i`. See hide-identity to set the server to not respond
        to such queries.

version: <string>
        Returns the specified version string when asked for ``CH TXT
        version.server``, and ``version.bind`` queries. Default is the compiled
        package version. See hide-version to set the server to not respond to
        such queries.

nsid: <string>
        Add the specified nsid to the EDNS section of the answer when queried
        with an NSID EDNS enabled packet. As a sequence of hex characters or
        with ascii\_ prefix and then an ascii string. Same as commandline option
        :option:`-I`.

logfile: <filename>
        Log messages to the logfile. The default is to log to stderr and syslog
        (with facility LOG_DAEMON). Same as commandline option :option:`-l`.

log-only-syslog: <yes or no>
        Log messages only to syslog. Useful with systemd so that print to stderr
        does not cause duplicate log strings in journald. Before syslog has been
        opened, the server uses stderr. Stderr is also used if syslog is not
        available. Default is no.

server-count: <number>
        Start this many NSD servers. Default is 1. Same as commandline option
        :option:`-N`.

cpu-affinity: <number> <number> ...
        Overall CPU affinity for NSD server(s). Default is no affinity.

server-N-cpu-affinity: <number>
        Bind NSD server specified by N to a specific core. Default is to have
        affinity set to every core specified in cpu-affinity. This setting only
        takes effect if cpu-affinity is enabled.

xfrd-cpu-affinity: <number>
        Bind xfrd to a specific core. Default is to have affinity set to every
        core specified in cpu-affinity. This setting only takes effect if
        cpu-affinity is enabled.

tcp-count: <number>
        The maximum number of concurrent, active TCP connections by each server.
        Default is 100. Same as commandline option :option:`-n`.

tcp-reject-overflow: <yes or no>
        If set to yes, TCP connections made beyond the maximum set by tcp-count
        will be dropped immediately (accepted and closed). Default is no.

tcp-query-count: <number>
        The maximum number of queries served on a single TCP connection. Default
        is 0, meaning there is no maximum.

tcp-timeout: <number>
        Overrides the default TCP timeout. This also affects zone transfers
        over TCP. The default is 120 seconds.

tcp-mss: <number>
        Maximum segment size (MSS) of TCP socket on which the server responds
        to queries. Value lower than common MSS on Ethernet (1220 for example)
        will address path MTU problem. Note that not all platform supports
        socket option to set MSS (TCP_MAXSEG). Default is system default MSS
        determined by interface MTU and negotiation between server and client.

outgoing-tcp-mss: <number>
        Maximum segment size (MSS) of TCP socket for outgoing XFR request to
        other namesevers. Value lower than common MSS on Ethernet (1220 for
        example) will address path MTU problem. Note that not all platform
        supports socket option to set MSS (TCP_MAXSEG). Default is system
        default MSS determined by interface MTU and negotiation between NSD and
        other servers.

ipv4-edns-size: <number>
        Preferred EDNS buffer size for IPv4. Default 1232.

ipv6-edns-size: <number>
        Preferred EDNS buffer size for IPv6. Default 1232.

pidfile: <filename>
        Use the pid file instead of the platform specific default, usually
        :file:`/var/run/nsd.pid`. Same as commandline option :option:`-P`. With
        ``""`` there is no pidfile, for some startup management setups, where a
        pidfile is not useful to have.

port: <number>
        Answer queries on the specified port. Default is 53. Same as commandline
        option :option:`-p`.

statistics: <number>
        If not present no statistics are dumped. Statistics are produced every
        number seconds. Same as commandline option :option:`-s`.

chroot: <directory>
        NSD will chroot on startup to the specified directory. Note that if
        elsewhere in the configuration you specify an absolute pathname to a
        file inside the chroot, you have to prepend the chroot path. That way,
        you can switch the chroot option on and off without having to modify
        anything else in the configuration. Set the value to ``""`` (the empty
        string) to disable the chroot. By default ``""`` is used. Same as
        commandline option :option:`-t`.

username: <username>
        After binding the socket, drop user privileges and assume the username.
        Can be username, id or id.gid. Same as commandline option :option:`-u`.

zonesdir: <directory>
        Change the working directory to the specified directory before accessing
        zone files. Also, NSD will access **database**, **zonelist-file**,
        **logfile**, **pidfile**, **xfrdfile**, **xfrdir**, **server-key-file**,
        **server-cert-file**, **control-key-file** and **control-cert-file**
        relative to this directory. Set the value to ``""`` (the empty string)
        to disable the change of working directory. By default
        :file:`"/etc/nsd"` is used.

difffile: <filename>
        Ignored, for compatibility with NSD3 config files.

xfrdfile: <filename>
        The soa timeout and zone transfer daemon in NSD will save its state to
        this file. State is read back after a restart. The state file can be
        deleted without too much harm, but timestamps of zones will be gone. If
        it is configured as ``""``, the state file is not used, all slave zones
        are checked for updates upon startup. For more details see the section
        on zone expiry behavior of NSD. Default is
        :file:`/var/db/nsd/xfrd.state`.

xfrdir: <directory>
        The zone transfers are stored here before they are processed. A
        directory is created here that is removed when NSD exits. Default is
        :file:`/tmp`.

xfrd-reload-timeout: <number>
        If this value is -1, xfrd will not trigger a reload after a zone
        transfer. If positive xfrd will trigger a reload after a zone transfer,
        then it will wait for the number of seconds before it will trigger a new
        reload. Setting this value throttles the reloads to once per the number
        of seconds. The default is 1 second.

verbosity: <level>
        This value specifies the verbosity level for (non-debug) logging.
        Default is 0. 1 gives more information about incoming notifies and
        zone transfers. 2 lists soft warnings that are encountered. 3 prints
        more information.

        Verbosity 0 will print warnings and errors, and other events that are
        important to keep NSD running.

        Verbosity 1 prints additionally messages of interest. Successful
        notifies, successful incoming zone transfer (the zone is updated),
        failed incoming zone transfers or the inability to process zone updates.

        Verbosity 2 prints additionally soft errors, like connection resets
        over TCP. And notify refusal, and axfr request refusals.

hide-version: <yes or no>
        Prevent NSD from replying with the version string on CHAOS class
        queries. Default is no.

hide-identity: <yes or no>
        Prevent NSD from replying with the identity string on CHAOS class
        queries. Default is no.

drop-updates: <yes or no>
        If set to yes, drop received packets with the UPDATE opcode. Default is
        no.

use-systemd: <yes or no>
        This option is deprecated and ignored. If compiled with libsystemd,
        NSD signals readiness to systemd and use of the option is not necessary.

log-time-ascii: <yes or no>
        Log time in ascii, if "no" then in seconds epoch. Default is yes. This
        chooses the format when logging to file. The print- out via syslog has a
        timestamp formatted by syslog.

round-robin: <yes or no>
        Enable round robin rotation of records in the answer. This changes the
        order of records in the answer and this may balance load across them.
        The default is no.

minimal-responses: <yes or no>
        Enable minimal responses for smaller answers. This makes pack- ets
        smaller. Extra data is only added for referrals, when it is really
        necessary. This is different from the --enable-minimal-responses
        configure time option, that reduces packets, but ex- actly to the
        fragmentation length, the nsd.conf option reduces packets as small as
        possible. The default is no.

confine-to-zone: <yes or no>
        If set to yes, additional information will not be added to the response
        if the apex zone of the additional information does not match the apex
        zone of the initial query (E.G. CNAME resolution). Default is no.

refuse-any: <yes or no>
        Refuse queries of type ANY. This is useful to stop query floods trying
        to get large responses. Note that rrl ratelimiting also has type ANY as
        a ratelimiting type. It sends truncation in response to UDP type ANY
        queries, and it allows TCP type ANY queries like normal. The default is
        no.

zonefiles-check: <yes or no>
        Make NSD check the mtime of zone files on start and sighup. If you
        disable it it starts faster (less disk activity in case of a lot of
        zones). The default is yes. The nsd-control reload command reloads
        zone files regardless of this option.

zonefiles-write: <seconds>
        Write changed secondary zones to their zonefile every N seconds. If the
        zone (pattern) configuration has ``""`` zonefile, it is not written. Zones
        that have received zone transfer updates are written to their zonefile.
        Default is 0 (disabled) when there is a database, and 3600 (1 hour) when
        database is ``""``. The database also commits zone transfer contents. You
        can configure it away from the default by putting the config statement
        for zonefiles-write: after the database: statement in the config file.

rrl-size: <numbuckets>
        This option gives the size of the hashtable. Default 1000000. More
        buckets use more memory, and reduce the chance of hash collisions.

rrl-ratelimit: <qps>
        The max qps allowed (from one query source). Default is on (with a
        suggested 200 qps). If set to 0 then it is disabled (unlimited rate),
        also set the whitelist-ratelimit to 0 to disable rate-limit processing.
        If you set verbosity to 2 the blocked and unblocked subnets are
        logged. Blocked queries are blocked and some receive TCP fallback
        replies. Once the rate limit is reached, NSD begins dropping responses.
        However, one in every "rrl-slip" number of responses is allowed, with
        the TC bit set. If slip is set to 2, the outgoing response rate will be
        halved. If it's set to 3, the outgoing response rate will be one-third,
        and so on. If you set rrl-slip to 10, traffic is reduced to 1/10th.
        Ratelimit options rrl-ratelimit, rrl-size and rrl-whitelist-ratelimit
        are updated when nsd-control reconfig is done (also the zone-specific
        ratelimit options are updated).

rrl-slip: <numpackets>
        This option controls the number of packets discarded before we send back
        a SLIP response (a response with "truncated" bit set to one). 0 disables
        the sending of SLIP packets, 1 means every query will get a SLIP
        response. Default is 2, cuts traffic in half and legit users have a fair
        chance to get a +TC response.

rrl-ipv4-prefix-length: <subnet>
        IPv4 prefix length. Addresses are grouped by netblock. Default 24.

rrl-ipv6-prefix-length: <subnet>
        IPv6 prefix length. Addresses are grouped by netblock. Default 64.

rrl-whitelist-ratelimit: <qps>
        The max qps for query sorts for a source, which have been whitelisted.
        Default on (with a suggested 2000 qps). With the rrl-whitelist option
        you can set specific queries to receive this qps limit instead of the
        normal limit. With the value 0 the rate is unlimited.

answer-cookie: <yes or no>
        Enable to answer to requests containig DNS Cookies as specified in :RFC:`7873`. Default is no.

cookie-secret: <128 bit hex string>
        Servers in an anycast deployment need to be able to verify each other's
        DNS Server Cookies. For this they need to share the secret used to
        construct and verify the DNS Cookies. Default is a 128 bits random
        secret generated at startup time. This option is ignored if a
        **cookie-secret-file** is present. In that case the secrets from that
        file are used in DNS Cookie calculations.

cookie-secret-file: <filename>
        File from which the secrets are read used in DNS Cookie calculations.
        When this file exists, the secrets in this file are used and the secret
        specified by the **cookie-secret** option is ignored. Default is
        :file:`/etc/nsd/nsd_cookiesecrets.txt`

        The content of this file must be manipulated with the
        **add_cookie_secret**, **drop_cookie_secret** and
        **activate_cookie_secret** commands to the :manpage:`nsd-control(8)`
        tool. Please see that manpage how to perform a safe cookie secret
        rollover.

tls-service-key: <filename>
        If enabled, the server provides TLS service on TCP sockets with the TLS
        service port number. The port number (853) is configured with tls-port.
        To turn it on, create an interface: option line in config with @port
        appended to the IP-address. This creates the extra socket on which the
        DNS over TLS service is provided.

        The file is the private key for the TLS session. The public certificate
        is in the tls-service-pem file. Default is ``""``, turned off. Requires
        a restart (a reload is not enough) if changed, because the private key
        is read while root permissions are held and before chroot (if any).

tls-service-pem: <filename>
        The public key certificate pem file for the tls service. Default is
        ``""``, turned off.

tls-service-ocsp: <filename>
        The ocsp pem file for the tls service, for OCSP stapling. Default is
        ``""``, turned off. An external process prepares and updates the OCSP
        stapling data. Like this,

        .. code-block:: text

                openssl ocsp -no_nonce \
                -respout /path/to/ocsp.pem \
                -CAfile /path/to/ca_and_any_intermediate.pem \
                -issuer /path/to/direct_issuer.pem \
                -cert /path/to/cert.pem \
                -url "$( openssl x509 -noout -text -in /path/to/cert.pem |
                grep 'OCSP - URI:' | cut -d: -f2,3 )"

tls-port: <number>
        The port number on which to provide TCP TLS service, default is
        853, only interfaces configured with that port number as @number
        get DNS over TLS service.

tls-cert-bundle: <filename>
        If null or ``""``, the default verify locations are used. Set it to the
        certificate bundle file, for example
        :file:`"/etc/pki/tls/certs/ca-bundle.crt"`. These certificates are used
        for authenticating Transfer over TLS (XoT) connections.

Remote Control
^^^^^^^^^^^^^^

The **remote-control:** clause is used to set options for using the
:manpage:`nsd-control(8)` tool to give commands to the running NSD server. It is
disabled by default, and listens for localhost by default. It uses TLS over TCP
where the server and client authenticate to each other with self-signed
certificates. The self-signed certificates can be generated with the
*nsd-control-setup* tool. The key files are read by NSD before the chroot and
before dropping user permissions, so they can be outside the chroot and readable
by the superuser only.

control-enable: <yes or no>
        Enable remote control, default is no.

control-interface: <ip4 or ip6 | interface name | absolute path>
        NSD will bind to the listed addresses to service control requests (on
        TCP). Can be given multiple times to bind multiple ip-addresses. Use
        0.0.0.0 and ::0 to service the wildcard interface. If none are given
        NSD listens to the localhost 127.0.0.1 and ::1 interfaces for control,
        if control is enabled with control-enable.

        If an interface name is used instead of ip4 or ip6, the list of IP
        addresses associated with that interface is picked up and used at server
        start.

        With an absolute path, a unix local named pipe is used for control.
        The file is created with user and group that is configured and access
        bits are set to allow members of the group access. Further access can
        be controlled by setting permissions on the directory containing the
        control socket file. The key and cert files are not used when control is
        via the named pipe, because access control is via file and directory
        permission.

control-port: <number>
        The port number for remote control service. 8952 by default.

server-key-file: <filename>
        Path to the server private key, by default
        :file:`/etc/nsd/nsd_server.key`. This file is generated by the
        nsd-control-setup utility. This file is used by the nsd server, but not
        by *nsd-control*.

server-cert-file: <filename>
        Path to the server self signed certificate, by default
        :file:`/etc/nsd/nsd_server.pem`. This file is generated by the
        *nsd-control-setup* utility. This file is used by the nsd server, and
        also by *nsd-control*.

control-key-file: <filename>
        Path to the control client private key, by default
        :file:`/etc/nsd/nsd_control.key`. This file is generated by the
        *nsd-control-setup* utility. This file is used by *nsd-control*.

control-cert-file: <filename>
        Path to the control client certificate, by default
        :file:`/etc/nsd/nsd_control.pem`. This certificate has to be signed with
        the server certificate. This file is generated by the
        *nsd-control-setup* utility. This file is used by *nsd-control*.

Pattern Options
^^^^^^^^^^^^^^^

The **pattern:** clause is used to denote a set of options to apply to some
zones. The same zone options as for a zone are allowed.

name: <string>
        The name of the pattern. This is a (case sensitive) string. The pattern
        names that start with "_implicit_" are used internally for zones that
        have no pattern (they are defined in *nsd.conf* directly).

include-pattern: <pattern-name>
        The options from the given pattern are included at this point in this
        pattern. The referenced pattern must be defined above this one.

<zone option>: <value>
        The zone options such as **zonefile**, **allow-query**,
        **allow-notify**, **request-xfr**, **allow-axfr-fallback**, **notify**,
        **notify-retry**, **provide-xfr**, **zonestats**, and
        **outgoing-interface** can be given. They are applied to the patterns
        and zones that include this pattern.

Zone Options
^^^^^^^^^^^^

For every zone the options need to be specified in one **zone:** clause. The
access control list elements can be given multiple times to add multiple
servers. These elements need to be added explicitly.

For zones that are configured in the *nsd.conf* config file their settings are
hardcoded (in an implicit pattern for themselves only) and they cannot be
deleted via delzone, but remove them from the config file and repattern.

name: <string>
        The name of the zone. This is the domain name of the apex of the zone.
        May end with a ``'.'`` (in FQDN notation). For example "example.com",
        "sub.example.net.". This attribute must be present in each zone.

zonefile: <filename>
        The file containing the zone information. If this attribute is present
        it is used to read and write the zone contents. If the attribute is
        absent it prevents writing out of the zone.

        The string is processed so that one string can be used (in a pattern)
        for a lot of different zones. If the label or character does not exist
        the percent-character is replaced with a period for output (i.e. for the
        third character in a two letter domain name).

        **%s** is replaced with the zone name.

        **%1** is replaced with the first character of the zone name.

        **%2** is replaced with the second character of the zone name.

        **%3** is replaced with the third character of the zone name.

        **%z** is replaced with the toplevel domain name of the zone.

        **%y** is replaced with the next label under the toplevel domain.

        **%x** is replaced with the next-next label under the toplevel domain.

allow-query: <ip-spec> <key-name | NOKEY | BLOCKED>
        Access control list. When at least one **allow-query** option is
        specified, then the in the **allow-query** options specified addresses
        are are allowed to query the server for the zone. Queries from unlisted
        or specifically BLOCKED addresses are discarded. If NOKEY is given no
        TSIG signature is required. BLOCKED supersedes other entries, other
        entries are scanned for a match in the order of the statements. Without
        **allow-query** options, queries are allowed from any IP address without
        TSIG key (which is the default).

        The ip-spec is either a plain IP address (IPv4 or IPv6), or can be a
        subnet of the form ``1.2.3.4/24``, or masked like
        ``1.2.3.4&255.255.255.0`` or a range of the form ``1.2.3.4-1.2.3.25``.
        Note the ip-spec ranges do not use spaces around the ``/``, ``&``, ``@``
        and ``-`` symbols.

allow-notify: <ip-spec> <key-name | NOKEY | BLOCKED>
        Access control list. The listed (primary) address is allowed to send
        notifies to this (secondary) server. Notifies from unlisted or
        specifically BLOCKED addresses are discarded. If NOKEY is given no TSIG
        signature is required. BLOCKED supersedes other entries, other entries
        are scanned for a match in the order of the statements.

        The ip-spec is either a plain IP address (IPv4 or IPv6), or can be a
        subnet of the form ``1.2.3.4/24``, or masked like
        ``1.2.3.4&255.255.255.0`` or a range of the form ``1.2.3.4-1.2.3.25``. A
        port number can be added using a suffix of @number, for example
        ``1.2.3.4@5300`` or ``1.2.3.4/24@5300`` for port 5300. Note the ip-spec
        ranges do not use spaces around the ``/``, ``&``, ``@`` and ``-``
        symbols.

request-xfr: [AXFR|UDP] <ip-address> <key-name | NOKEY> [tls-auth-name]
        Access control list. The listed address (the master) is queried for
        AXFR/IXFR on update. A port number can be added using a suffix of
        @number, for example ``1.2.3.4@5300``. The specified key is used during
        AXFR/IXFR. If tls-auth-name is included, the specified tls-auth clause
        will be used to perform authenticated XFR-over-TLS.

        If the AXFR option is given, the server will not be contacted with IXFR
        queries but only AXFR requests will be made to the server. This allows
        an NSD secondary to have a master server that runs NSD. If the AXFR
        option is left out then both IXFR and AXFR requests are made to the
        master server.

        If the UDP option is given, the secondary will use UDP to transmit the
        IXFR requests. You should deploy TSIG when allowing UDP transport, to
        authenticate notifies and zone transfers. Otherwise, NSD is more
        vulnerable for Kaminsky-style attacks. If the UDP option is left out
        then IXFR will be transmitted using TCP.

        If a tls-auth-name is given then TLS (by default on port 853) will be
        used for all zone transfers for the zone. If authentication of the
        master based on the specified tls-auth authentication information
        fails, the XFR request will not be sent. Support for TLS 1.3 is required
        for XFR-over-TLS.

allow-axfr-fallback: <yes or no>
        This option should be accompanied by request-xfr. It (dis)allows
        NSD (as secondary) to fallback to AXFR if the primary name
        server does not support IXFR. Default is yes.

size-limit-xfr: <number>
        This option should be accompanied by request-xfr. It specifies XFR
        temporary file size limit. It can be used to stop very large zone
        retrieval, that could otherwise use up a lot of memory and disk space.
        If this option is 0, unlimited. Default value is 0.

notify: <ip-address> <key-name | NOKEY>
        Access control list. The listed address (a secondary) is notified of
        updates to this zone. A port number can be added using a suffix of
        @number, for example ``1.2.3.4@5300``. The specified key is used to sign
        the notify. Only on secondary configurations will NSD be able to detect
        zone updates (as it gets notified itself, or refreshes after a time).

notify-retry: <number>
        This option should be accompanied by notify. It sets the number of
        retries when sending notifies.

provide-xfr: <ip-spec> <key-name | NOKEY | BLOCKED>
        Access control list. The listed address (a secondary) is allowed to
        request AXFR from this server. Zone data will be provided to the
        address. The specified key is used during AXFR. For unlisted or BLOCKED
        addresses no data is provided, requests are discarded. BLOCKED
        supersedes other entries, other entries are scanned for a match in the
        order of the statements. NSD provides AXFR for its secondaries, but IXFR
        is not implemented (IXFR is implemented for request-xfr, but not for
        provide-xfr).

        The ip-spec is either a plain IP address (IPv4 or IPv6), or can be a
        subnet of the form ``1.2.3.4/24``, or masked like
        ``1.2.3.4&255.255.255.0`` or a range of the form ``1.2.3.4-1.2.3.25``. A
        port number can be added using a suffix of @number, for example
        ``1.2.3.4@5300`` or ``1.2.3.4/24@5300`` for port 5300. Note the ip-spec
        ranges do not use spaces around the the ``/``, ``&``, ``@`` and ``-``
        symbols.

outgoing-interface: <ip-address>
        Access control list. The listed address is used to request AXFR|IXFR (in
        case of a secondary) or used to send notifies (in case of a primary).

        The ip-address is a plain IP address (IPv4 or IPv6). A port number can
        be added using a suffix of @number, for example ``1.2.3.4@5300``.

max-refresh-time: <seconds>
        Limit refresh time for secondary zones. This is the timer which checks
        to see if the zone has to be refetched when it expires. Normally the
        value from the SOA record is used, but this option restricts that value.

min-refresh-time: <seconds>
        Limit refresh time for secondary zones.

max-retry-time: <seconds>
        Limit retry time for secondary zones. This is the timer which retries
        after a failed fetch attempt for the zone. Normally the value from the
        SOA record is used, followed by an exponential backoff, but this option
        restricts that value.

min-retry-time: <seconds>
        Limit retry time for secondary zones.

min-expire-time: <seconds or refresh+retry+1>
        Limit expire time for secondary zones. The value can be expressed either
        by a number of seconds, or the string "refresh+retry+1". With the latter
        the expire time will be lower bound to the refresh plus the retry value
        from the SOA record, plus 1. The refresh and retry values will be
        subject to the bounds configured with max-refresh-time,
        min-refresh-time, max-retry-time and min-retry-time if given.

zonestats: <name>
        When compiled with ``--enable-zone-stats`` NSD can collect statistics
        per zone. This name gives the group where statistics are added to. The
        groups are output from nsd-control stats and stats_noreset. Default is
        ``""``. You can use ``"%s"`` to use the name of the zone to track its
        statistics. If not compiled in, the option can be given but is ignored.

include-pattern: <pattern-name>
        The options from the given pattern are included at this point. The
        referenced pattern must be defined above this zone.

rrl-whitelist: <rrltype>
        This option causes queries of this rrltype to be whitelisted, for this
        zone. They receive the whitelist-ratelimit. You can give multiple lines,
        each enables a new rrltype to be whitelisted for the zone. Default has
        none whitelisted. The rrl-type is the query classification that the NSD
        RRL employs to make different types not interfere with one another. The
        types are logged in the loglines when a subnet is blocked (in verbosity
        2). The RRL classification types are: nxdomain, error, referral, any,
        rrsig, wildcard, nodata, dnskey, positive, all.

multi-master-check: <yes or no>
        Default no. If enabled, checks all masters for the last version. It uses
        the higher version of all the configured masters. Useful if you have
        multiple masters that have different version numbers served.

Key Declarations
^^^^^^^^^^^^^^^^

The **key:** clause establishes a key for use in access control lists. It has
the following attributes.

name: <string>
        The key name. Used to refer to this key in the access control list. The
        key name has to be correct for tsig to work. This is because the key
        name is output on the wire.

algorithm: <string>
        Authentication algorithm for this key. Such as hmac-md5, hmac-sha1,
        hmac-sha224, hmac-sha256, hmac-sha384 and hmac-sha512. Can also be
        abbreviated as 'sha1', 'sha256'. Default is sha256. Algorithms are only
        available when they were compiled in (available in the crypto library).

secret: <base64 blob>
        The base64 encoded shared secret. It is possible to put the **secret:**
        declaration (and base64 blob) into a different file, and then to
        **include:** that file. In this way the key secret and the rest of the
        configuration file, which may have different security policies, can be
        split apart. The content of the secret is the agreed base64 secret
        content. To make it up, enter a password (its length must be a multiple
        of 4 characters, A-Za-z0-9), or use dev-random output through a base64
        encode filter.

TLS Auth Declarations
^^^^^^^^^^^^^^^^^^^^^

The **tls-auth:** clause establishes authentication attributes to use when
authenticating the far end of an outgoing TLS connection used in access
control lists for XFR-over-TLS. It has the following attributes.

name: <string>
        The tls-auth name. Used to refer to this TLS authentication information
        in the access control list.

auth-domain-name: <string>
        The authentication domain name as defined in :RFC:`8310`.

client-cert: <file name of clientcert.pem>
        If you want to use mutual TLS authentication, this is where the client
        certificates can be configured that NSD uses to connect to the upstream
        server to download the zone. The client public key pem cert file can be
        configured here. Also configure a private key with client-key.

client-key: <file name of clientkey.key>
        If you want to use mutual TLS authentication, the private key file can
        be configured here for the client authentication.

client-key-pw: <string>
        If the client-key file uses a password to decrypt the key before it can
        be used, then the password can be specified here as a string. It is
        possible to include other config files with the include: option, and
        this can be used to move that sensitive data to another file, if you
        wish.

DNSTAP Logging Options
^^^^^^^^^^^^^^^^^^^^^^

DNSTAP support, when compiled in, is enabled in the **dnstap:** section. This
starts a collector process that writes the log information to the destination.

dnstap-enable: <yes or no>
        If dnstap is enabled. Default no. If yes, it connects to the dnstap
        server and if any of the dnstap-log-..-messages options is enabled it
        sends logs for those messages to the server.

dnstap-socket-path: <file name>
        Sets the unix socket file name for connecting to the server that is
        listening on that socket. Default is :file:`"/var/run/nsd-dnstap.sock"`.

dnstap-send-identity: <yes or no>
        If enabled, the server identity is included in the log messages. Default
        is no.

dnstap-send-version: <yes or no>
        If enabled, the server version if included in the log messages. Default
        is no.

dnstap-identity: <string>
        The identity to send with messages, if ``""`` the hostname is used.
        Default is ``""``.

dnstap-version: <string>
        The version to send with messages, if ``""`` the package version is
        used. Default is ``""``.

dnstap-log-auth-query-messages: <yes or no>
        Enable to log auth query messages. Default is no. These are client
        queries to NSD.

dnstap-log-auth-response-messages: <yes or no>
        Enable to log auth response messages. Default is no. These are responses
        from NSD to clients.

NSD Configuration for BIND9 Hackers
-----------------------------------

BIND9 is a name server implementation with its own configuration file
format, *named.conf(5)*. BIND9 types zones as 'Master' or 'Slave'.

Slave zones
^^^^^^^^^^^
For a slave zone, the master servers are listed. The master servers are
queried for zone data, and are listened to for update notifications.
In NSD these two properties need to be configured separately, by listing
the master address in allow-notify and request-xfr statements.

In BIND9 you only need to provide allow-notify elements for any extra
sources of notifications (i.e. the operators), NSD needs to have
allow-notify for both masters and operators. BIND9 allows additional
transfer sources, in NSD you list those as request-xfr.

Here is an example of a slave zone in BIND9 syntax.

.. code-block:: text

        # Config file for example.org options {
            dnssec-enable yes;
        };

        key tsig.example.org. {
                algorithm hmac-md5;
                secret "aaaaaabbbbbbccccccdddddd";
        };

        server 162.0.4.49 {
                keys { tsig.example.org. ; };
        };

        zone "example.org" {
                type slave;
                file "secondary/example.org.signed";
                masters { 162.0.4.49; };
        };

For NSD, DNSSEC is enabled automatically for zones that are signed. The
**dnssec-enable** statement in the options clause is not needed. In NSD keys are
associated with an IP address in the access control list statement, therefore
the **server{}** statement is not needed. Below is the same example in an NSD
config file.

.. code-block:: text

        # Config file for example.org
        key:
                name: tsig.example.org.
                algorithm: hmac-md5
                secret: "aaaaaabbbbbbccccccdddddd"

        zone:
                name: "example.org"
                zonefile: "secondary/example.org.signed"
                # the master is allowed to notify and will provide zone data.
                allow-notify: 162.0.4.49 NOKEY
                request-xfr: 162.0.4.49 tsig.example.org.

Notice that the master is listed twice, once to allow it to send notifies to
this slave server and once to tell the slave server where to look for updates
zone data. More allow-notify and request-xfr lines can be added to specify more
masters.

It is possible to specify extra allow-notify lines for addresses that are also
allowed to send notifications to this slave server.

Master zones
^^^^^^^^^^^^

For a master zone in BIND9, the slave servers are listed. These slave servers
are sent notifications of updated and are allowed to request transfer of the
zone data. In NSD these two properties need to be configured separately.

Here is an example of a master zone in BIND9 syntax.

.. code-block:: text

        zone "example.nl" {
                type master;
                file "example.nl";
        };

In NSD syntax this becomes:

        zone:
                name: "example.nl"
                zonefile: "example.nl"
                # allow anybody to request xfr.
                provide-xfr: 0.0.0.0/0 NOKEY
                provide-xfr: ::0/0 NOKEY

                # to list a slave server you would in general give
                # provide-xfr: 1.2.3.4 tsig-key.name.
                # notify: 1.2.3.4 NOKEY

Other
^^^^^

NSD is an authoritative only DNS server. This means that it is meant as a
primary or secondary server for zones, providing DNS data to DNS resolvers and
caches. BIND9 can function as an authoritative DNS server, the configuration
options for that are compared with those for NSD in this section. However, BIND9
can also function as a resolver or cache. The configuration options that BIND9
has for the resolver or caching thus have no equivalents for NSD.

Files
-----

/var/db/nsd/nsd.db
        default :command:`NSD` database

/etc/nsd/nsd.conf
        default :command:`NSD` configuration file

See Also
--------

:manpage:`nsd(8)`, :manpage:`nsd-checkconf(8)`, :manpage:`nsd-control(8)`

Bugs
----

**nsd.conf** is parsed by a primitive parser, error messages may not be to the
point.
