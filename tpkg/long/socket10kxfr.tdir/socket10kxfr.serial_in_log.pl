#!/usr/bin/env perl

BEGIN{ $| = 1; }

if (scalar @ARGV != 3) {
	print "usage: serials_in_log.pl file nzones serial\n";
	exit 1;
}
my $filenm  = shift @ARGV;
my $nzones  = shift @ARGV;
my $serial  = shift @ARGV;
$nzones++;
my @seen = ((0,) x $nzones);
my $processed = 0;

print "updated to serial $serial: ";

my $start = time();
my $p = 0;
my $t = 0;
while (time() - $start <= 180) {
	open(LOG, $filenm) || die "could not open $filenm\n";
	while (<LOG>) {
		if (/zone (\d+)\.tld serial \d+ is updated to $serial/
		    and $1 >= 0 and $1 < $nzones and $seen[$1] == 0) {

			$seen[$1] = 1;
			$processed += 1;
			if ($processed == $nzones) {
				my $nt = (time() - $start);
				my $bw = $t == $nt ? "" 
						   :   ($processed - $p) 
						     / ($nt - $t);
				my $tbw = $nt == 0 ? $processed 
						   : $processed / $nt;
				print("$nzones/$bw/$tbw\n");
				exit(0);
			}
		}
	}
	my $nt = (time() - $start);
	if ($nt > $t && $p ne $processed) {
		my $bw = ($processed - $p) / ($nt - $t);
		$t = $nt;
		$p = $processed;
		print("$processed/$bw ");
	}
	sleep 1;
}
exit(-1);

