BaseName: xfr_update
Version: 2.0
Description: Test that ixfr is used to update nsd.db, retained for next start
CreationDate: Fri Apr 05 15:44:06 CEST 2011
Maintainer: Wouter Wijngaards
Category: 
Component:
CmdDepends: 
Depends: 
Help:
Pre: xfr_udp.pre
Post: xfr_udp.post
Test: xfr_udp.test
AuxFiles: xfr_udp.known_good, xfr_udp.conf, xfr_udp.conf, xfr_udp.zone, 
	xfr_udp.datafile
Passed:
Failure:
