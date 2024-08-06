nsd-checkzone(8)
================

Synopsis
--------

:command:`nsd-checkzone` [:option:`-h`] zonename zonefile

Description
-----------

:command:`nsd-checkzone` reads a DNS zone file and checks it for errors. It
prints errors to stderr. On failure it exits with nonzero exit status.

This is used to check files before feeding them to the :manpage:`nsd(8)` daemon.

Options
-------

.. option::  -h

    Print usage help information and exit.

zonename
    The name of the zone to check, eg. "example.com".

zonefile
    The file to read, eg. :file:`zones/example.com.zone.signed`.

.. option::  -p

    Print the zone contents to stdout if the zone is ok. This prints the
    contents as it has been parsed, not literally a copy of the input, but
    as printed by the formatting routines in NSD, much like the nsd-control
    command write does.

See Also
--------

:manpage:`nsd(8)`, :manpage:`nsd-checkconf(8)`