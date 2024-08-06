Grammar for DNS Zone Files
==========================

.. Note:: It is near impossible to write a clean lexer/grammar for DNS
          (:rfc:`1035`) zone files. At first it looks like it is easy to make
          such a beast, but when you start implementing it the details make it
          messy.

Since as early as NSD 1.4, the parser relies on Bison and Flex, tools for
building programs that handle structured input. Compared to the previous
implementation there is a slight decrease in speed (10-20%), but as the zone
compiler is not critical to the performance of NSD, this not too relevant. The
lexer part is located in the file `zlexer.lex
<https://github.com/NLnetLabs/nsd/blob/master/zlexer.lex>`_, the grammar is in
`zparser.y <https://github.com/NLnetLabs/nsd/blob/master/zparser.y>`_.

Zone File Lexer
---------------

Finding a good grammar and lexer for BIND zone files is rather hard. There are
no real keywords and the meaning of most of the strings depends on the position
relative to the other strings. An example, the following is a valid SOA record:

.. code-block:: text

    $ORIGIN example.org.
        SOA    soa    soa    ( 1 2 3 4 5 6 )

This SOA records means the administrator has an email address of
``soa@example.org``. and the first nameserver is named ``soa.example.org``. Both
completely valid. The numbers are of course totally bogus.

Another example would be:

.. code-block:: text

    $ORIGIN example.org.
        SOA    soa    soa    ( 1 2 ) ( 3 4 ) ( 5 ) ( 6 )

The parsing of parentheses was also not trivial. Whitespace is also significant
in zonefiles. The TAB before SOA has to be returned as previous_domain token by
the lexer. Newlines inside parentheses are returned as SPACE which works but
required some changes in the definitions of the resource records.

As shown above a simple ``grep -i`` for SOA does not do the trick. The lexer
takes care of this tricky part by using an extra variable ``in_rr`` which is an
enum containing: ``outside``, ``expecting_dname``, ``after_dname``,
``reading_type``. The semantics are as follows:

 - ``outside``, not in an RR (start of a line or a $-directive);
 - ``expecting_dname``, parse owner name of RR;
 - ``after_dname``, parse ttl, class;
 - ``reading_type``, we expect the RR type now;

With ``in_rr`` the lexer can say that in the first example above the first SOA
is the actual record type, because it is located after a TAB. After we have
found the TAB we set ``in_rr`` to ``after_dname`` which means we actually are
expecting a RR type.

Again this is also not trivial because the class (IN) and TTL are also optional,
if there are not specified we should substitute the current defaults from the
zone we are parsing (this happens in the grammar). A DNS zone file is further
complicated by the unknown RR record types.

Zone File Grammar
-----------------

After the lexer was written the grammar itself is quite clean and nice. The
basic idea is that every RR consists of single line (the parentheses are handled
in the lexer - so this really is the case). If a line is not a RR it is either a
comment, empty or a $-directive. Some $-directives are handled inside the lexer
($INCLUDE) while others ($ORIGIN) must be dealt with inside the grammar.

An RR is defined as:

.. code-block:: text

    rr:     ORIGIN SP rrrest

and:

.. code-block:: text

    rrrset: classttl rtype

And then we have a whole list of:

.. code-block:: text

    rtype: TXT sp rdata_txt
           | DS sp rdata_ds
           | AAAA sp rdata_aaaa

which are then parsed by using the ``rdata_`` rule. Shown here is the one for
the SOA:

.. code-block:: text

    rdata_soa:  dname sp dname sp STR sp STR sp STR sp STR sp STR trail
        {
            /* convert the soa data */
            zadd_rdata_domain( current_parser, $1); /* prim. ns */
            zadd_rdata_domain( current_parser, $3); /* email */
            zadd_rdata_wireformat( current_parser,  \
                    zparser_conv_rdata_period(zone_region, $5.str) ); /* serial */
            zadd_rdata_wireformat( current_parser,  \
                    zparser_conv_rdata_period(zone_region, $7.str) ); /* refresh */
            zadd_rdata_wireformat( current_parser,  \
                    zparser_conv_rdata_period(zone_region, $9.str) ); /* retry */
            zadd_rdata_wireformat( current_parser,  \
                    zparser_conv_rdata_period(zone_region, $11.str) ); /* expire */
            zadd_rdata_wireformat( current_parser,  \
                    zparser_conv_rdata_period(zone_region, $13.str) ); /* minimum */

            /* XXX also store the minium in case of no TTL? */
            if ( (current_parser->minimum = zparser_ttl2int($11.str) ) == -1 )
                current_parser->minimum = DEFAULT_TTL;
        };

The semantic actions in the grammar store the RR data for processing by the zone
compiler. The resulting database is then used by NSD the serve the data.
