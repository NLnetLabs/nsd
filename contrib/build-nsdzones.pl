#!/usr/bin/perl

##########################################################################
#
# Quick perlscript to rebuild the nsd.zones file from a typical BIND8/9
# named.conf .
#
# Copyright 2003 - Bruce Campbell and the RIPE NCC.
# No warranty, you know the drill.
#

use strict;
use Getopt::Long;
use lib ".";
use DNS::Config;
use DNS::Config::File;
use DNS::Config::File::Bind9;
use DNS::Config::File::Nsd;
use vars qw($VERSION);
$VERSION = do { my @r=(q$Revision: 1.1 $=~/\d+/g); sprintf "%d."."%02d"x$#r,@r};

## Invoke main().
&main();

## exit.  The rest of the file is just subroutines.
exit(3);

## Define the options and routines.
## This complicated affair ensures that there is just one place 
sub meta_retrieve (){
	my ($str1, $str2) = (@_);

	## This defines the arguments and their subroutines.
	my %metaargs = (
			"help"	=> {
				getopt	=> "",
				usage	=> "Display this Help message.",
				sub	=> \&do_misc,
				precedence => "yes"
				},
			"warranty" => {
				getopt	=> "",
				usage	=> "Display the Warranty message.",
				sub	=> \&do_misc,
				},
			"copyright" => {
				getopt	=> "",
				usage	=> "Display the Copyright message.",
				sub	=> \&do_misc,
				},
			"bindconf" => {
				getopt	=> "=s@",
				expects => "<file>",
				usage	=> "The BIND conf file(s).",
				sub	=> \&do_readconf,
				},
			"nsdzones" => {
				getopt	=> "=s",
				expects => "<file>",
				usage	=> "The nsd.zones output file.",
				sub	=> \&do_nsd,
				},
			"nsdcconf" => {
				getopt	=> "=s",
				expects => "<file>",
				usage	=> "The nsdc.conf output file.",
				sub	=> \&do_nsd,
				},
			"nsdkeysdir" => {
				getopt	=> "=s",
				expects => "<file>",
				usage	=> "Where to put TSIG keys.  This could also be in the pseudo bindconf file, as 'nsdkeysdir /some/dir;'",
				},
			"root" => {
				getopt	=> "",
				usage	=> "If present, will output the '.' zone which is not included by default.\n(NSD is an authoritative-only server.  If you tell it to serve '.' from the \n hints file, it is not the valid '.' zone.)",
				},
		);

	## Possible return types.
	my @retarr = ();
	my $retstr = undef;
	my $retwhich = "str";

	## Work out what we're doing.
	if( $str1 eq 'getopts' ){
		$retwhich = "array";
		foreach my $poppy( keys %metaargs ){
			if( defined( $metaargs{"$poppy"}{"getopt"} ) ){
				push @retarr, "$poppy" . $metaargs{"$poppy"}{"getopt"};
			}
		}
	}elsif( $str1 eq 'precedence' ){
		$retwhich = "array";
		foreach my $poppy( keys %metaargs ){
			if( defined( $metaargs{"$poppy"}{"precedence"} ) ){
				push @retarr, "$poppy";
			}
		}
	}elsif( $str1 eq 'args' ){
		$retwhich = "array";
		foreach my $poppy( keys %metaargs ){
			push @retarr, "$poppy";
		}
	}elsif( defined( $metaargs{"$str1"} ) ){
		$retstr = $metaargs{"$str1"}{"$str2"};
	}

	## Return the appropriate thing.
	if( $retwhich eq 'array' ){
		return( @retarr );
	}else{
		return( $retstr );
	}
}

## Define Main (remember to invoke &main() ).
sub main () {

	## Build GetOptions from %metaargs
	my @GetOpts = &meta_retrieve( 'getopts' );

	## Get the Options.
	my %opts = ();
	GetOptions( \%opts, @GetOpts );

	## Get the Precedents and put them into a hash for better handling.
	my %precedents = ();
	foreach my $poppy( &meta_retrieve( 'precedence' ) ){
		$precedents{"$poppy"}++;
	}

	## See if we ran anything.
	my $didrun=0;

	my @args = &meta_retrieve( 'args' );
	## Lets handle the ones with precedence first.
	foreach my $poppy( @args ){
		if( defined( $precedents{"$poppy"} ) && defined( $opts{"$poppy"} )  ){
			my $this_sub = &meta_retrieve( "$poppy", "sub" );
			if( defined( $this_sub ) ){
				eval { &$this_sub( $poppy, %opts ); };
				$didrun++;
			}
		}
	}

	## And lets handle the ones that are left.
	foreach my $poppy( @args ){
		if( ! defined( $precedents{"$poppy"} ) && defined( $opts{"$poppy"} ) ){
			my $this_sub = &meta_retrieve( "$poppy", "sub" );
			if( defined( $this_sub ) ){
				eval { &$this_sub( $poppy, %opts ); };
				$didrun++;
			}
		}
	}

	## Final comment before we exit.
	if( $didrun == 0 ){
		print STDERR "$0: No/Incomplete arguments found.  Try --help\n";
	}
}

###############################################################################
##                          M E T H O D S
###############################################################################

## Do a rebuild of the nsd zone file.
sub do_nsd {
	my ($opt, %opts) = (@_);

	# Temporary output.
	my @localtime = localtime( time );
	my $lastline = sprintf( "; Generated at %d | %04d-%02d-%02d %02d:%02d:%02d localtime", time, ( 1900 + $localtime[5] ) , ( 1 + $localtime[4] ) , $localtime[3], $localtime[2], $localtime[1], $localtime[0] );

	my $retval = undef;
	my $dns_config = &do_readconf( "bindconf", %opts );

	# Do we have it?
	if( ! defined( $dns_config ) ){
		print STDERR "Please specify where to find the BIND named.conf file\n";
	}else{
		# Convert it.
		my $tref = ref( $dns_config->config );
		my $nsd = new DNS::Config::File::Nsd( "tmpfile", $dns_config->config );
		my $tref2 = ref( $opts{$opt} );

		if( $opt eq "nsdzones" ){
			if( ! defined( $opts{"root"} ) ){
				# We need to walk the tree and delete the
				# root zone, if present.  Ugh.
				my $config = $nsd->config();
				my @statements = $config->statements;
				foreach my $statement( @statements ){
					my $tref = ref( $statement );
					next unless( $tref eq "DNS::Config::Statement::Zone" );
					next unless( $statement->name eq '.' );
					$config->delete( $statement );
				}
				# $nsd->config( $config );
				$nsd = new DNS::Config::File::Nsd( "tmpfile", $config );
			}
			# Dump out the nsd.zone information.
			$nsd->dump_nsd_zones( $opts{$opt} );

			if( open( MYOUT, ">> " . $opts{$opt} ) ){
				print MYOUT "# $lastline\n";
				close( MYOUT );
			}
			$retval=1;
		}elsif( $opt eq "nsdcconf" ){

			if( defined( $opts{"nsdkeysdir"} ) ){
				# The keys are elsewhere.
				$nsd->nsdkeysdir( $opts{"nsdkeysdir"} );

				# dump the tsig stuff.
				$nsd->dump_tsig( $opts{"nsdkeysdir"} );
			}else{
				# dump the tsig stuff.
				$nsd->dump_tsig();
			}

			# Finally dump the nsdc.conf file.
			$nsd->dump_nsdc( $opts{$opt} );

			if( open( MYOUT, ">> " . $opts{$opt} ) ){
				print MYOUT "# $lastline\n";
				close( MYOUT );
			}
			$retval=1;
		}else{
			print STDERR "Huh - something funny - I do not recognise $opt\n";
		}
	}

	return( $retval );
}


## Process all the 'misc' commands.

sub do_misc() {
	my ( $opt, %opts ) = (@_);
	my $retval = 0;
	my $ldate = '$Date: 2003/02/26 11:09:15 $';
	my $lauthor = '$Author: alexis $';
	if( $opt eq "warranty" ){
		$retval = 1;
		print << 'EOM' ;

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

EOM

		exit 0;
	}elsif( $opt eq "copyright" ){
		print << 'EOM' ;

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 1, or (at your option)
any later version.

EOM
		exit 0;
	}elsif( $opt eq "version" ){
		print "$0: Version: $VERSION Last Update: $ldate by $lauthor\n";
		exit 0;
	}elsif( $opt eq "help" ){
		print "$0: Version: $VERSION Last Update: $ldate by $lauthor\n";

		print "Valid Options:\n";

		my @args = &meta_retrieve( 'args', '' );
		foreach my $arg ( @args ){
			print "\t--$arg\t";
			if( defined( &meta_retrieve( $arg, 'expects' ) ) ){
				print &meta_retrieve( $arg, 'expects' );
			}
			print "\n";
			if( defined( &meta_retrieve( $arg, 'usage' ) ) ){
				print "\t\t" . &meta_retrieve( $arg, 'usage' );
			}
			print "\n";
		}
		print "\nNOTE: Will append '.nsd' to zones with type 'hint'.  This due to nsd wanting\nan SOA record on all zone files, and BIND not needing them.  Please remember\nto add an SOA record to these files.\n";
		exit 0;
	}
}

{ # Begin local variable scope

my $dns_config = undef;

sub do_forgetconf {
	$dns_config = undef;
	return( $dns_config );
}

sub do_readconf {
	my ($opt, %opts) = (@_);

	if( ! defined( $dns_config ) ){

		# We sometimes get odd stuff.
		my $filename = $opts{$opt};
		if( ref( $filename ) ){
			$filename = ${$filename}[0];
		}

		$dns_config = new DNS::Config::File( type => 'Bind9', 
						file => $filename,
						);

		# Parse it.
		$dns_config->parse( $filename );
	}


	return( $dns_config );
}

sub do_getconf {
	return( $dns_config );
}


} # End local variable scope
