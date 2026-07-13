BaseName: unbounded_cname_chain
Version: 1.0
Description: Check whether following long CNAME chains crashed NSD (only on ASAN builds)
CreationDate: ma 13 jul 2026 10:20:09 CEST
Maintainer: Willem Toorop
Category:
Component:
CmdDepends: python3
Depends:
Help:
Pre: unbounded_cname_chain.pre
Post: unbounded_cname_chain.post
Test: unbounded_cname_chain.test
AuxFiles: unbounded_cname_chain.conf unbounded_cname_chain.generate_zone.py
Passed:
Failure:
