#!/usr/bin/perl

# strip all non essential stuff from
# the dig output. Should be something left
# that can be used for comparisons.

while(<>) {
	if ( /^;; ([A-Z]+) SECTION:/i ) {
		if ( $1 =~ /QUESTION/ ) { next;}
		print ";; $1\n";
		next;
	}
	if ( /^;[a-z0-9]+/i ) {
		# this is the question
		s/^;//;
		print;
		next;
	}

	if ( /;; flags: (.*)/ ) {
		$up = uc($1);
		print ";; FLAGS: $up\n";
		next;
	}

	if ( /;; .* opcode: +(.*), id:/ ) {
		$up = uc($1);
		print ";; OPCODE: $up\n";
		next;
	}

	if ( /^;/ or /^$/ ) { next; }

	# quick hack the not entirely correct fixes the TCR
	s/TYPE46/RRSIG/;
	s/TYPE47/NSEC/;
	s/TYPE48/DNSKEY/;

	print;
}
