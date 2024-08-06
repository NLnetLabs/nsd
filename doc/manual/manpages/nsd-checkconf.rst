nsd-checkconf(8)
================

Synopsis
--------

:command:`nsd-checkconf` :option:`-v` :option:`-f` :option:`-h` [:option:`-o`
``option``] [:option:`-z` ``zonename``] [:option:`-p` ``pattern``] [:option:`-s`
``keyname``] [:option:`-t` ``tlsauthname``] configfile

Description
-----------

:command:`nsd-checkconf` reads a configuration file. It prints parse errors to
standard error, and performs additional checks on the contents. The configfile
format is described in :manpage:`nsd.conf(5)`.

The utility of this program is to check a config file for errors before using it
in :manpage:`nsd(8)`. This program can also be used for shell scripts to access
the nsd config file, using the :option:`-o` and :option:`-z` options.

Options
-------

.. option:: -v

        After reading print the options to standard output in configfile format.
        Without this option, only success or parse errors are reported.

.. option:: -f

        Print full pathname when used with files, like with :option:`-o`
        pidfile. This includes the chroot in the way it is applied to the
        pidfile.

.. option:: -h

        Print usage help information and exit.

.. option:: -o option

        Return only this option from the config file. This option can be used in
        conjunction  with the :option:`-z` and the :option:`-p` option, or
        without them to query the server: section. The special value zones
        prints  out  a list of configured zones. The special value patterns
        prints out a list of configured patterns.

        This option can be used to parse the config file from the shell. If the
        :option:`-z` option is given, but the :option:`-o` option is not given,
        nothing is printed.

.. option:: -s keyname

        Prints the key secret (base64 blob) configured for this key in the
        config file. Used to help shell scripts parse the config file.

.. option:: -t tls-auth

        Prints the authentication domain name configured for this tls-auth
        clause in the config file. Used to help shell scripts parse the config
        file.

.. option:: -p pattern

        Return the option specified with :option:`-o` for the given pattern
        name.

.. option:: -z zonename

        Return the option specified with :option:`-o` for zone ``zonename``.

        If this option is not given, the server section of the config file is
        used.

        The  :option:`-o`,  :option:`-s`  and :option:`-z` option print
        configfile options to standard output.

Files
-----

/etc/nsd/nsd.conf
        default NSD configuration file

See Also
--------

:manpage:`nsd(8)`, :manpage:`nsd.conf(5)`, :manpage:`nsd.control(8)`

