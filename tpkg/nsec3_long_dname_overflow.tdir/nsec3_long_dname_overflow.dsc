BaseName: nsec3_long_dname_overflow
Version: 1.0
Description: Test wildcard prehashing for NSEC3 zones with long (255b) name 
CreationDate: di  9 jun 2026 14:42:19 CEST
Maintainer: Willem Toorop
Category:
Component:
CmdDepends:
Depends: 0000_nsd-compile.tpkg
Help:
Pre:
Post:
Test: nsec3_long_dname_overflow.test
AuxFiles: nsec3_long_dname_overflow.conf
	nsec3_long_dname_overflow.zone-253.signed
	nsec3_long_dname_overflow.zone-254.signed
	nsec3_long_dname_overflow.zone-255.signed  
Passed:
Failure:
