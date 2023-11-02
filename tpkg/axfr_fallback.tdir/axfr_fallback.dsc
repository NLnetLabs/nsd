BaseName: axfr_fallback
Version: 1.0
Description: Test whether NSD falls back to AXFR/TCP when IXFR/UDP fails
CreationDate: Mon Sep  1 12:08:35 CEST 2008
Maintainer: Matthijs Mekking
Category: running
Component:
CmdDepends: 
Depends: 0000_nsd-compile.tpkg
Help: axfr_fallback.help
Pre: axfr_fallback.pre
Post: axfr_fallback.post
Test: axfr_fallback.test
AuxFiles: axfr_fallback.known_good, axfr_fallback.conf, axfr_fallback.datafile, 
	axfr_fallback.zone
Passed:
Failure:
