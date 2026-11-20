Zone Verification
=================

Zone verification was introduced in NSD 4.6.0 and lets you check zone updates
before NSD publishes them. An external program examines the candidate zone and
tells NSD whether to accept or reject it. This provides a checkpoint between
receiving new zone data and making it available to clients and downstream
secondaries.

Typical uses include checking DNSSEC signatures, validating ZONEMD records,
checking required records, or enforcing requirements specific to your publication process.

NSD coordinates verification but does not perform the checks itself. The
checks depend on the external verifier you configure.

.. raw:: html

   <style>
   .nlnetlabs-zone-diagram { color-scheme: light dark; }
   body[data-theme="light"] .nlnetlabs-zone-diagram { color-scheme: light; }
   body[data-theme="dark"] .nlnetlabs-zone-diagram { color-scheme: dark; }
   @media (prefers-reduced-motion: reduce) {
     .nlnetlabs-zone-diagram { display: none; }
   }
   </style>

How it works
------------

During a reload, NSD prepares updated zone data while its existing query
processes continue serving the previous version. For zones with verification
enabled, NSD runs the configured verifier before publishing the update.

.. figure:: ../resources/images/nlnetlabs-nsd-zone-verification.svg
   :figclass: nlnetlabs-zone-diagram
   :alt: A verifying NSD checks updates from a hidden primary before publishing them to public secondaries.
   :width: 100%

   Example deployment showing an accepted update. The verifying NSD
   receives the transfer, runs the external verifier and makes the accepted
   zone available to public secondaries, which continue answering queries.

The verifier communicates its result through its exit status:

- **Zero:** accept the candidate zone.
- **Non-zero:** reject the update and retain the previous version.
- **Timeout:** terminate the verifier and reject the update.

NSD can provide the candidate zone to the verifier through standard input
in presentation format. Alternatively, the verifier can retrieve the
complete candidate zone through AXFR from a separate verification interface.
AXFR transfers the records in DNS wire format and can be substantially
faster than reading presentation-format data from standard input.

For large zones, a verifier can first obtain the currently published SOA
serial from the normal query interface, then request an IXFR from that
serial through the verification interface. When an incremental transfer
is available, this allows checks that support incremental validation to
process only the changes. The verifier should also handle a full AXFR
response if an incremental transfer is unavailable.

The verification interface exposes candidate data before NSD publishes it
through the normal query service.

.. important::

   Retaining the previous version does not make it valid indefinitely.
   DNSSEC signatures can expire, and secondary zones remain subject to
   normal zone-expiry rules. Rejected updates need operational attention.

Before you begin
----------------

You will need:

- A working NSD configuration.
- An external verifier suitable for the checks you want to perform.
- Access to the verifier and its dependencies from NSD's runtime
  environment, including any configured chroot.
- A way to monitor rejected updates and verifier failures.

Test the verifier independently with representative zone data before
enabling it in production. Confirm that it returns zero for acceptable
data and a non-zero exit status for data you intend to reject.

Enable verification
-------------------

The following example uses ``ldns-verify-zone`` to check zone data and
requires a valid ZONEMD record through the ``-Z`` option. A single ``-Z``
also permits verification of an unsigned zone using its ZONEMD record;
use ``-ZZ`` if the zone must additionally be validly DNSSEC signed.

Add a top-level ``verify:`` section to ``nsd.conf``:

.. code-block:: text

   verify:
       enable: yes
       verify-zones: yes
       verifier: ldns-verify-zone -V2 -Z
       verifier-feed-zone: yes
       verifier-timeout: 60

This enables verification for zones by default and passes candidate zone
data to the verifier through standard input.

NSD executes the verifier directly, without a shell. Write the executable
and its arguments as separate tokens, as shown above; do not quote the
whole command as one string. Put pipelines or multiple checks in an
executable script.

The timeout of 60 seconds is an example, not a recommended value. Measure
verification time with your own zones and allow for expected load. A timeout
that is too short can reject otherwise acceptable updates. The default is 0 
seconds which means the verifier may take as long as it needs.

Check the configuration before applying it:

.. code-block:: console

   nsd-checkconf /etc/nsd/nsd.conf

Use the configuration path appropriate for your installation.

Enable verification selectively
-------------------------------

To verify only selected zones, disable verification by default:

.. code-block:: text

   verify:
       enable: yes
       verify-zones: no
       verifier: ldns-verify-zone -V2 -Z
       verifier-feed-zone: yes
       verifier-timeout: 60

Then add the following option to an existing ``zone:`` or ``pattern:``
section:

.. code-block:: text

   verify-zone: yes

Zones and patterns can also override the verifier command, input method
and timeout. This allows different publication checks for different
groups of zones.

Adding custom checks
--------------------

A verifier can be a script that runs an existing tool such as
``ldns-verify-zone`` or ``validns`` and performs additional checks specific
to your zones or publication process. You do not need to implement a DNSSEC
validator yourself.

Additional checks can enforce requirements specific to your publication
process. For example, a script could reject a zone with fewer records
than expected, or require a TXT record added by the provisioning system.
Such a record could indicate when the zone was generated or how many
records it should contain.

When combining checks on data received through standard input, save the
candidate zone to a temporary file so that each tool can read the complete
input. Use a DNS-aware parser for record checks, and return zero only if
every check succeeds.

Configure the executable script as the verifier, for example:

.. code-block:: text

   verifier: /usr/local/libexec/check-zone
   verifier-feed-zone: yes

The script, its interpreter and any tools it calls must be available to
NSD's runtime user, including inside a configured chroot. If it creates
temporary files, it also needs a writable directory and should remove
those files on exit.

NSD supplies environment variables describing the candidate zone and
verification interfaces. These include ``VERIFY_ZONE`` and
``VERIFY_ZONE_ON_STDIN``, together with address and port information for
verifiers that retrieve data through DNS queries.

Your verifier should:

- Inspect the candidate data supplied by NSD, rather than querying the
  currently published zone by mistake.
- Return zero only when all required checks pass.
- Return a non-zero status when a check fails or cannot be completed.
- Produce useful diagnostic output so that failures can be investigated.

See the `Verifier options
<../manpages/nsd.conf.html#Verifier_options>`_ reference for the complete
environment-variable list and configuration options.

The approach is similar to `Cascade review hooks
<https://cascade.docs.nlnetlabs.nl/en/latest/review-hooks.html>`_: a script
combines existing tools and signals approval or rejection through its
exit status. The scripts are not directly interchangeable. Cascade uses
its own configuration and environment variables and the script retrieves
the candidate zone through AXFR; NSD can also supply it on standard input.

.. note::

   NSD can load and serve ZONEMD records, but does not generate or validate
   their digests itself. An external verifier such as
   ``ldns-verify-zone -Z`` can require a ZONEMD record and verify the zone
   digest.

To check the DNSSEC chain of trust, a verifier can use ``unbound-host``
with a configuration supplied through ``-C``. Configure a stub zone
pointing to NSD's verification interface and a trust anchor above the
candidate zone. The ``-v`` option reports the validation status.

Check the SOA record and at least one other signed record type. This
tests the chain of trust for those responses, rather than every record
in the zone. If successful DNSSEC validation is required, the verifier
must require a ``secure`` result; an ``insecure`` result is not sufficient.
Because the stub zone directs queries to the verification interface,
this check does not test the published delegation's glue.

Test before deployment
----------------------

Use a test zone to exercise both acceptance and rejection:

#. Submit an update that should pass your checks. Confirm that NSD
   publishes the new SOA serial and expected records.
#. Submit an update that should fail. Confirm that the previous serial
   and records remain available.
#. Test a verifier error or timeout. Confirm that the update is rejected
   and that the failure is visible to your monitoring.
#. Correct the rejected update and confirm that publication resumes.

For DNSSEC checks, include a deliberately invalid signed zone in your
tests. Testing only valid input does not establish that the verifier
detects the failures you care about.

Reloading and publication
-------------------------

Existing query workers serve current data while a reload process prepares
the candidate database. For an accepted transfer, the sequence is:

#. A query worker receives an authorised NOTIFY and passes it directly to
   ``xfrd`` through an internal pipe.
#. ``xfrd`` retrieves the update and writes it to a file for that transfer.
   Transfers can also be triggered by the normal refresh timer.
#. The main process forks a reload process, which applies the transferred
   data to its copy of the database. Unchanged memory pages can remain
   shared through copy-on-write.
#. The external verifier checks the candidate zone.
#. After acceptance, new query workers inherit the updated database and
   take over service. The previous workers and main process retire.

.. figure:: ../resources/images/nlnetlabs-nsd-reload.svg
   :figclass: nlnetlabs-zone-diagram
   :alt: NSD prepares and verifies a candidate database while existing workers serve current data, then starts new workers and retires the old processes.
   :width: 100%

   Simplified process lifecycle for an accepted update. ``db`` is the
   current database; ``db′`` is the updated database. ``xfrd`` manages
   transfers.

If verification fails, NSD discards the rejected update and retries the
reload without it. The existing query workers continue serving while
this happens. The diagram shows the successful path for one update;
a reload can include updates to multiple zones.

Operational considerations
--------------------------

Verification adds processing time to zone publication. Its cost depends
on the zone contents, the checks performed and the verifier implementation.

The ``verifier-count`` option limits how many verifier processes may run
concurrently. Tune concurrency and timeouts together, considering CPU and
memory use as well as the acceptable delay before updates become visible.

Monitor repeated verification failures, publication delays and the
remaining validity of the currently served data. A rejected update can
protect the service from bad data, but it also means that intended changes
have not reached clients.

Further reading
---------------

- `nsd.conf(5): Verifier options
  <../manpages/nsd.conf.html#Verifier_options>`_
- `Zone verification in NSD: design and background
  <https://blog.nlnetlabs.nl/zone-verification-in-nsd/>`_
