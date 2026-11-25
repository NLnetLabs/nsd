NSD documentation
=================

NSD is an open-source authoritative DNS server developed by NLnet Labs. It
publishes DNS data for the zones it hosts, answering queries from resolvers.
It runs in environments ranging from an organisation's internal domains to
DNS infrastructure serving the Internet's root and top-level domains.
NSD focuses on authoritative service: it does not perform recursive resolution
or sign zones.

This manual explains how to install, configure and operate NSD. For an overview
of its capabilities, read `About NSD
<https://nlnetlabs.nl/projects/nsd/about/>`__. For the engineering behind its
query processing, zone updates and publication controls, see `NSD in depth
<https://nlnetlabs.nl/projects/nsd/in-depth/>`__.

Get started
-----------

Start with :doc:`installation`, then follow the :doc:`configuration guide
<configuration>`. The :doc:`zone-file example <zonefile>` explains how to
prepare DNS data for a zone. Configure NSD for its role as a primary or
secondary server, including which systems may send notifications and transfer
zone data.

Configure and operate
---------------------

Use the topic guides to adapt NSD to your deployment:

- **Zone distribution:** authenticate transfers with :doc:`TSIG
  <running/using-tsig>` and manage zone membership through
  :doc:`catalog zones <catalog-zones>`.
- **Publication checks:** configure :doc:`zone verification
  <running/zone-verification>` to run an external verifier before publishing
  updates, and understand :doc:`zone expiry <running/zone-expiry>` when a
  secondary cannot refresh its data.
- **Performance:** :doc:`tune resource use <running/tuning>` and choose
  :doc:`listening interfaces <running/interfaces>`. The
  :doc:`XDP guide <xdp>` covers the experimental fast path for UDP queries.
- **Monitoring and control:** read about :doc:`logging and traffic reporting
  <running/logging>` and use :doc:`nsd-control <manpages/nsd-control>` to
  inspect zone status, retrieve statistics and manage a running server.

Look up an option or command
----------------------------

The :doc:`nsd.conf reference <manpages/nsd.conf>` describes configuration
options and their defaults, including transfer access controls, XFR over TLS
and monitoring settings. Use :doc:`nsd-checkconf <manpages/nsd-checkconf>` to
check a configuration file and :doc:`nsd-checkzone <manpages/nsd-checkzone>` to
check a zone file before loading it. DNSSEC signing and signature verification
require separate tools.

The manual pages in the navigation cover the daemon and command-line tools.
See :doc:`log diagnosis <reference/log-diagnosis>` for help interpreting
messages, :doc:`configure options <reference/configure-options>` for build-time
settings and :doc:`RFC compliance <reference/rfc-compliance>` for supported
standards.

Get help and contribute
-----------------------

Ask operational questions and discuss deployments on the `NLnet Labs community
forum <https://community.nlnetlabs.nl/>`__. Organisations that need assistance
from the development team and service-level commitments can obtain
`professional support and consultancy
<https://nlnetlabs.nl/services/contracts/>`__.

Report software bugs in the `NSD issue tracker
<https://github.com/NLnetLabs/nsd/issues>`__. For suspected security
vulnerabilities, use the `security reporting instructions
<https://nlnetlabs.nl/security-report/>`__.

Corrections and improvements to this manual are welcome through issues and
pull requests in the `NSD repository <https://github.com/NLnetLabs/nsd/>`__.
The documentation lives in ``doc/manual`` and is licensed under
`Creative Commons Attribution 3.0
<https://creativecommons.org/licenses/by/3.0/>`__, with attribution to
NLnet Labs.


.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: Getting Started

   installation
   configuration
   zonefile
   catalog-zones
   xdp

.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: Running

   running/logging
   running/using-tsig
   running/zone-verification
   running/zone-expiry
   running/interfaces
   running/tuning

.. toctree::
   :hidden:
   :maxdepth: 1
   :caption: Manual Pages

   manpages/nsd
   manpages/nsd-checkconf
   manpages/nsd-checkzone
   manpages/nsd.conf
   manpages/nsd-control

.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: Reference

   reference/configure-options
   reference/log-diagnosis
   reference/rfc-compliance

.. history
.. authors
.. license
