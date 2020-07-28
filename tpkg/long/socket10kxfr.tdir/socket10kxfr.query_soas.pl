#!/usr/bin/env perl

BEGIN{ $| = 1; }

use Net::DNS;
if (scalar @ARGV != 3) {
	print "usage: query_soas.pl port nzones serial\n";
	exit 1;
}
my $port   = shift @ARGV;
my $nzones = shift @ARGV;
my $serial = shift @ARGV;
my $res = new Net::DNS::Resolver(nameservers => ["127.0.0.1"], port => $port);

sub checkSerials {
	my $s = shift;
	my @tlds = (0..($nzones-1));
	my $start = time();
	while (@tlds) {
		if (time() - $start > 360) {
			exit(-1);
		}
		my @recheck = ();
		$#recheck = -1;
		while (my $i = pop @tlds) {
			my $p = $res->query("$i.tld", "SOA");
			if ($p) {
				my @a = grep {$_->type eq "SOA"} $p->answer;
				if ($a[0]->serial < $s) {
					push @recheck, $i;
				}
			}
			if ((scalar @tlds % 1000) == 0) {
				print ($nzones - (scalar @tlds + scalar @recheck));
				print " ";
			}
		}
		print ($nzones - (scalar @tlds + scalar @recheck));
		print " ";
		@tlds = @recheck;
		sleep 1;
	}
}

print "all $nzones serial == $serial: ";
checkSerials $serial;
print "\n";

