BaseName: svcb_uint16_wrap
Version: 1.0
Description: Test whether NSD fails SVCB out of bounds checks
CreationDate: do  4 jun 2026 10:16:05 CEST
Maintainer: Willem Toorop
Category: running
Component:
CmdDepends: 
Depends: 0000_nsd-compile.tpkg
Help: svcb_uint16_wrap.help
Pre: svcb_uint16_wrap.pre
Post: svcb_uint16_wrap.post
Test: svcb_uint16_wrap.test
AuxFiles: svcb_uint16_wrap.conf svcb_uint16_wrap.datafile
	svcb_uint16_wrap.zone svcb_uint16_wrap.problem-zone
	svcb_uint16_wrap.nsd_control.key svcb_uint16_wrap.nsd_control.pem
	svcb_uint16_wrap.nsd_server.key svcb_uint16_wrap.nsd_server.pem
	
Passed:
Failure:
