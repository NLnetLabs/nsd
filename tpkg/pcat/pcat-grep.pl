#!/usr/bin/perl

# take a numerical range and ranges and 
# only show those ranges or not (-v)
# single numbers: 4
# ranges: 5-10 (inclusive)
# seperated by comma's
# -v reverse

use strict;

my %numbers = ();
my $reverse = 0;
my $i;
my $k;

foreach my $r (@ARGV) {

        if ($r eq "-v") {
                $reverse = 1;
                next;
        }
        
        if ($r =~ /-/) {
                my ($s, $e) = split /-/, $r;
                
                if ($s > $e) {
                        next;
                }

                for ($i = $s; $i <= $e; $i++) {
                        $numbers{$i} = 1;
                }
                next;
        }
        $numbers{$r} = 1;
}

# read in the input, pcat style
my $line; my $left; my $right;
$i = 1;
my $print = 0;
while(<STDIN>) {
        if ($i % 4 == 1) {
                s/^q: //;  # kill it, if we do query diff
                
                ($left, $right) = split /:/, $_;
                foreach $k (keys %numbers) {
                        if ($k == $left) {
                                if ($reverse == 1) {
                                        $print = 0;
                                } else {
                                        $print = 1;
                                }
                                last;
                        }
                        if ($reverse == 1) {
                                $print = 1;
                        } else {
                                $print = 0;
                        }
                }
        }        
        if ($print == 1) {
                print $_;
        }
        if ($i % 4 == 0) {
                if ($reverse == 1) {
                        $print = 1;
                } else {
                        $print = 0;
                }
        }
        $i++;
}
