#!/usr/bin/env python3
# generate_zone.py
import sys
chars = [i for i in range(256) if chr(i).isprintable()
                               and chr(i) not in ' ."()@$;\\X*'
                               and not chr(i).islower()
                               and i != 194]

z = b'''$ORIGIN .
$TTL 3600
@ SOA . . 1 3600 900 604800 300
X CNAME %c
''' % chars[0]
def enc(i):
    if i < len(chars):
        return b'%c' % chars[i]
    else:
        h, l = int(i / len(chars)) - 1, int(i % len(chars))
        return b'%c%c' % (chars[h], chars[l])
for i in range(10499):
    z += enc(i) + b' CNAME ' + enc(i+1) + b' ; %d\n' % i
z += enc(10499) + b' TXT target\n'

with open('unbounded_cname_chain.zone', 'wb') as fh:
    fh.write(z)

