nsd-control(8)
==============

Synopsis
--------

:command:`nsd-control` [:option:`-c` ``cfgfile``] [:option:`-s` ``server``] command

Description
-----------

:command:`nsd-control` performs remote administration on the :manpage:`nsd(8)`
DNS server. It reads the configuration file, contacts the nsd server over TLS,
sends the command and displays the result.

The available options are:

.. option:: -h

        Show the version and commandline option help.

.. option:: -c cfgfile

        The config file to read with settings. If not given the default
        config file :file:`/etc/nsd/nsd.conf` is used.

.. option:: -s server[@port]

        IPv4 or IPv6 address of the server to contact. If not given,
        the address is read from the config file.

Commands
--------

There are several commands that the server understands.

start
        Start the server. Simply execs :manpage:`nsd(8)`. The nsd executable is
        searched for in the **PATH** set in the environment. It is started with
        the config file specified using :option:`-c` or the default config file.

stop
        Stop the server. The server daemon exits.

reload [<zone>]
        Reload zonefiles and reopen logfile. Without argument reads changed
        zonefiles. With argument reads the zonefile for the given zone and loads
        it.

reconfig
        Reload nsd.conf and apply changes to TSIG keys and configuration
        patterns, and apply the changes to add and remove zones that are
        mentioned in the config. Other changes are not applied, such as
        listening ip address and port and chroot, also per-zone statistics are
        not applied. The pattern updates means that the configuration options
        for zones (request-xfr, zonefile, notify, ...) are updated. Also new
        patterns are available for use with the addzone command.

repattern
        Same as the reconfig option.

log_reopen
        Reopen the logfile, for log rotate that wants to move the logfile away
        and create a new logfile. The log can also be reopened with kill -HUP
        (which also reloads all zonefiles).

status
        Display server status. Exit code 3 if not running (the connection to the
        port is refused), 1 on error, 0 if running.

stats
        Output a sequence of name=value lines with statistics information,
        requires NSD to be compiled with this option enabled.

stats_noreset
        Same as stats, but does not zero the counters.

addzone <zone name> <pattern name>
        Add a new zone to the running server. The zone is added to the zonelist
        file on disk, so it stays after a restart. The pattern name determines
        the options for the new zone. For slave zones a zone transfer is
        immediately attempted. For zones with a zonefile, the zone file is
        attempted to be read in.

delzone <zone name>
        Remove the zone from the running server. The zone is removed from the
        zonelist file on disk, from the nsd.db file and from the memory. If it
        had a zonefile, this remains (but may be outdated). Zones configured
        inside nsd.conf itself cannot be removed this way because the daemon
        does not write to the nsd.conf file, you need to add such zones to the
        zonelist file to be able to delete them with the delzone command.

changezone <zone name> <pattern name>
        Change a zone to use the pattern for options. The zone is deleted and
        added in one operation, changing it to use the new pattern for the zone
        options. Zones configured in nsd.conf cannot be changed like this,
        instead edit the nsd.conf (or the included file in nsd.conf) and
        reconfig.

addzones
        Add zones read from stdin of nsd-control. Input is read per line, with
        name space patternname on a line. For bulk additions.

delzones
        Remove zones read from stdin of nsd-control. Input is one name per line.
        For bulk removals.

write [<zone>]
        Write zonefiles to disk, or the given zonefile to disk. Zones that have
        changed (via AXFR or IXFR) are written, or if the zonefile has not been
        created yet then it is created. Directory components of the zonefile
        path are created if necessary. With argument that zone is written if it
        was modified, without argument, all modified zones are written.

notify [<zone>]
        Send NOTIFY messages to slave servers. Sends to the IP addresses
        configured in the 'notify:' lists for the master zones hosted on this
        server. Usually NSD sends NOTIFY messages right away when a master zone
        serial is updated. If a zone is given, notifies are sent for that zone.
        These slave servers are supposed to initiate a zone transfer request
        later (to this server or another master), this can be allowed via the
        'provide-xfr:' acl list configuration. With argument that zone is
        processed, without argument, all zones are processed.

transfer [<zone>]
        Attempt to update slave zones that are hosted on this server by
        contacting the masters. The masters are configured via 'request-xfr:'
        lists. If a zone is given, that zone is updated. Usually NSD receives a
        NOTIFY from the masters (configured via 'allow-notify:' acl list) that a
        new zone serial has to be transferred. For zones with no content, NSD
        may have backed off from asking often because the masters did not
        respond, but this command will reset the backoff to its initial timeout,
        for frequent retries. With argument that zone is transferred, without
        argument, all zones are transferred.

force_transfer [<zone>]
        Force update slave zones that are hosted on this server. Even if the
        master hosts the same serial number of the zone, a full AXFR is
        performed to fetch it. If you want to use IXFR and check that the serial
        number increases, use the 'transfer' command. With argument that zone is
        transferred, without argument, all zones are transferred.

zonestatus [<zone>]
        Print state of the zone, the serial numbers and since when they have
        been acquired. Also prints the notify action (to which server), and zone
        transfer (and from which master) if there is activity right now. The
        state of the zone is printed as: 'master' (master zones), 'ok' (slave
        zone is up-to-date), 'expired' (slave zone has expired), 'refreshing'
        (slave zone has transfers active). The serial numbers printed are the
        'served-serial' (currently active), the 'commit-serial' (is in reload),
        the 'notified-serial' (got notify, busy fetching the data). The serial
        numbers are only printed if such a serial number is available. With
        argument that zone is printed, without argument, all zones are printed.

serverpid
        Prints the PID of the server process. This is used for statistics (and
        only works when NSD is compiled with statistics en- abled). This pid is
        not for sending unix signals, use the pid from nsd.pid for that, that
        pid is also stable.

verbosity <number>
        Change logging verbosity.

print_tsig [<key_name>]
        print the secret and algorithm for the TSIG key with that name. Or list
        all the tsig keys with their name, secret and algorithm.

update_tsig <name> <secret>
        Change existing TSIG key with name to the new secret. The secret is a
        base64 encoded string. The changes are only in-memory and are gone next
        restart, for lasting changes edit the nsd.conf file or a file included
        from it.

add_tsig <name> <secret> [algo]
        Add a new TSIG key with the given name, secret and algorithm. Without
        algorithm a default (hmac-sha256) algorithm is used. The secret is a
        base64 encoded string. The changes are only in-memory and are gone next
        restart, for lasting changes edit the nsd.conf file or a file included
        from it.

assoc_tsig <zone> <key_name>
        Associate the zone with the given tsig. The access control lists for
        notify, allow-notify, provide-xfr and request-xfr are adjusted to use
        the given key.

del_tsig <key_name>
        Delete the TSIG key with the given name. Prints error if the key is
        still in use by some zone. The changes are only in-memory and are gone
        next restart, for lasting changes edit the nsd.conf file or a file
        included from it.

add_cookie_secret <secret>
        Add or replace a cookie secret persistently. <secret> needs to be an 128
        bit hex string.

        Cookie secrets can be either active or staging. Active cookie secrets
        are used to create DNS Cookies, but verification of a DNS Cookie
        succeeds with any of the active or staging cookie secrets. The state of
        the current cookie secrets can be printed with the
        :command:`print_cookie_secrets` command.

        When there are no cookie secrets configured yet, the <secret> is added
        as active. If there is already an active cookie secret, the <secret> is
        added as staging or replacing an existing staging secret.

        To "roll" a cookie secret used in an anycast set. The new secret has to
        be added as staging secret to **all** nodes in the anycast set. When all
        nodes can verify DNS Cookies with the new secret, the new secret can be
        activated with the :command:`activate_cookie_secret` command. After all
        nodes have the new secret active for at least one hour, the previous
        secret can be dropped with the :command:`drop_cookie_secret` command.

        Persistence is accomplished by writing to a file which if configured
        with the **cookie-secret-file** option in the server section of the
        config file. The default value for that is:
        :file:`/etc/nsd/nsd_cookiesecrets.txt`.

drop_cookie_secret
        Drop the staging cookie secret.

activate_cookie_secret
        Make the current staging cookie secret active, and the current active
        cookie secret staging.

print_cookie_secrets
        Show the current configured cookie secrets with their status.

Exit Code
---------

The :command:`nsd-control` program exits with status code 1 on error, 0 on success.

Set Up
------

The setup requires a self-signed certificate and private keys for both the
server and client. The script :command:`nsd-control-setup` generates these in
the default run directory, or with :option:`-d` in another directory. If you
change the access control permissions on the key files you can decide who can
use :command:`nsd-control`, by default owner and group but not all users. The
script preserves private keys present in the directory. After running the script
as root, turn on **control-enable** in *nsd.conf*.

Statistics Counters
-------------------

The stats command shows a number of statistic counters.

num.queries
        number of queries received (the tls, tcp and udp queries added up).

serverX.queries
        number of queries handled by the server process. The number of server
        processes is set with the config statement **server-count**.

time.boot
        uptime in seconds since the server was started. With fractional seconds.

time.elapsed
        time since the last stats report, in seconds. With fractional seconds.
        Can be zero if polled quickly and the previous stats command resets the
        counters, so that the next gets a fully zero, and zero elapsed time,
        report.

size.db.disk
        size of nsd.db on disk, in bytes.

size.db.mem
        size of the DNS database in memory, in bytes.

size.xfrd.mem
        size of memory for zone transfers and notifies in xfrd process, excludes
        TSIG data, in bytes.

size.config.disk
        size of zonelist file on disk, excludes the nsd.conf size, in bytes.

size.config.mem
        size of config data in memory, kept twice in server and xfrd process, in
        bytes.

num.type.X
        number of queries with this query type.

num.opcode.X
        number of queries with this opcode.

num.class.X
        number of queries with this query class.

num.rcode.X
        number of answers that carried this return code.

num.edns
        number of queries with EDNS OPT.

num.ednserr
        number of queries which failed EDNS parse.

num.udp
        number of queries over UDP ip4.

num.udp6
        number of queries over UDP ip6.

num.tcp
        number of connections over TCP ip4.

num.tcp6
        number of connections over TCP ip6.

num.tls
        number of connections over TLS ip4. TLS queries are not part of num.tcp.

num.tls6
        number of connections over TLS ip6. TLS queries are not part of
        num.tcp6.

num.answer_wo_aa
        number of answers with NOERROR rcode and without AA flag, this includes
        the referrals.

num.rxerr
        number of queries for which the receive failed.

num.txerr
        number of answers for which the transmit failed.

num.raxfr
        number of AXFR requests from clients (that got served with reply).

num.rixfr
        number of IXFR requests from clients (that got served with reply).

num.truncated
        number of answers with TC flag set.

num.dropped
        number of queries that were dropped because they failed sanity check.

zone.master
        number of master zones served. These are zones with no 'request-xfr:'
        entries.

zone.slave
        number of slave zones served. These are zones with 'request-xfr'
        entries.

Files
-----

/etc/nsd/nsd.conf
        nsd configuration file.

/etc/nsd
        directory with private keys (nsd_server.key and nsd_control.key) and
        self-signed certificates (nsd_server.pem and nsd_control.pem).

See Also
--------

:manpage:`nsd.conf(5)`, :manpage:`nsd(8)`, :manpage:`nsd-checkconf(8)`

