#!/usr/bin/perl

# i'm too lazy to do this in sh...

# the typecode rollover is very simple:
# KEY -> DNSKEY
# SIG -> RRSIG
# NXT -> NSEC

# there can be situations where the rrtype is in a string but is
# not a real rrtype (base64 encoded strings). This script does not
# take those situations into account

while ( <> ) {

	s/KEY/DNSKEY/g;
	s/SIG/RRSIG/g;
	s/NXT/NSEC/g;

	print;

}
