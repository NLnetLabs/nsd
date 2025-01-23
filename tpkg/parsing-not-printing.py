#!/usr/bin/env python

printing = { (name[5:], int(num))
             for name, num in [ ln.split(maxsplit=3)[1:3]
                                for ln in open('dns.h')
                                if ln.startswith('#define TYPE_') ] 
             if int(num) != 41 and (int(num) < 128 or int(num) >= 256) }
parsing  = { (name[10:], int(num[1:-2]))
             for name, num in [ ln.split(maxsplit=3)[1:3]
                                for ln in open('simdzone/include/zone.h')
                                if ln.startswith('#define ZONE_TYPE_') ] }

if printing - parsing:
	print('implement parsing  for:', printing - parsing)
if parsing - printing:
	print('implement printing for:', parsing - printing)

