Zonefile example
================

On this page we give an example of a basic zone file and it's contents.

We recommend using the :command:`nsd-checkzone` tool to verify that you have a working zone.

Creating a zone
---------------

A minimal zone needs exactly one SOA (Source Of Authority) and one or more NS (Name Server) records. Refer to appropriate documentation of you need to learn about DNS basics.

.. code:: bash

	$ORIGIN example.com.
	$TTL 86400 ; default time-to-live for this zone

	example.com.   IN  SOA     ns.example.com. noc.dns.example.org. (
	        2020080302  ;Serial
	        7200        ;Refresh
	        3600        ;Retry
	        1209600     ;Expire
	        3600        ;Negative response caching TTL
	)

	; The nameservers that are authoritative for this zone.
					NS	example.com.

	; A and AAAA records are for IPv4 and IPv6 addresses respectively
	example.com.	A	192.0.2.1
					AAAA 2001:db8::3

	; A CNAME redirects from www.example.com to example.com
	www				CNAME   example.com.

	mail			MX	10	example.com.


.. could add this structure eventually: <name> <ttl> <class> <type> <rdata>
