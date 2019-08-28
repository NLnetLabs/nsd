BaseName: outgoing_ifc_denied
Version: 1.0
Description: Test whether notify on master and xfr request on slave uses correct 
	outgoing interfaces, but fail because no acl matches
CreationDate: Tue Sep 30 14:03:08 CEST 2008
Maintainer: Matthijs Mekking
Category: 
Component:
CmdDepends: 
Depends: 0000_nsd-compile.tpkg
Help: outgoing_ifc_denied.help
Pre: outgoing_ifc_denied.pre
Post: outgoing_ifc_denied.post
Test: outgoing_ifc_denied.test
AuxFiles: outgoing_ifc_denied.conf, outgoing_ifc_denied.known_good, outgoing_ifc_denied.zone, 
	outgoing_ifc_denied.conf2, outgoing_ifc_denied.zone2, outgoing_ifc_denied.known_good2
Passed:
Failure:
