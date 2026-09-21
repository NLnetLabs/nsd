#!/usr/bin/env python3


def svcb_rdlength(rdlength, for_zonefile = True):
    o = ''
    if for_zonefile:
        o += f'. 0 IN SVCB \\# {rdlength} 0001 00 ('.ljust(52)
        o += f'; {rdlength} -  3 = {rdlength - 3}\n'
    rdlength -= 3
    start = rdlength % 20
    if start:
        ngroups = int(start / 2)
        l = ['AAAA'] * ngroups
        if start - 2 * ngroups:
            l.append('AA')
        if len(l) > 5:
            l.insert(5, '')
        o += (' ' + ' '.join(l)).ljust(52)
        o += f'; {rdlength} - {start:2d} = {rdlength - start}\n'
        rdlength -= start
    while rdlength >= 20:
        o += f' AAAA AAAA AAAA AAAA AAAA  AAAA AAAA AAAA AAAA AAAA ; {rdlength} - 20 = {rdlength - 20}\n'
        rdlength -= 20
    assert(rdlength == 0)
    if for_zonefile:
        o += ')'
    return o + '\n'
with open('svcb_uint16_wrap.problem-zone', 'w') as fh:
    fh.write('. 0 IN SOA . . 1 3600 900 86400 60\n')
    fh.write(svcb_rdlength(65512))
with open('svcb_uint16_wrap.problem-zone2', 'w') as fh:
    fh.write('. 0 IN SOA . . 1 3600 900 86400 60\n')
    fh.write(svcb_rdlength(65535 - 6))
with open('svcb_uint16_wrap.datafile', 'w') as fh:
    fh.write('''$ORIGIN victim.
$TTL 300

ENTRY_BEGIN
MATCH opcode qtype qname
REPLY QUERY
REPLY NOTIMPL
REPLY AA AD
ADJUST copy_id          ; copy_id copies the ID from the query to the answer.
SECTION QUESTION
victim. IN IXFR
SECTION ANSWER
SECTION AUTHORITY
SECTION ADDITIONAL
ENTRY_END

ENTRY_BEGIN
MATCH TCP
ADJUST copy_id
HEX_ANSWER_BEGIN
 00 00 84 20             ; ID, Flags: QR, AA and AD
 00 00 00 01             ; QDCOUNT, ANCOUNT
 00 00 00 00             ; NSCOUNT, ARCOUNT

 06 76 69 63 74 69 6d 00 ; name        : victim.
 00 06                   ; type        : SOA
 00 01                   ; class       : IN
 00 00 01 2c             ; TTL         :   300
 00 16                   ; RDLEN       :    22
 00 00                   ; mname, rname: . .
 00 00 00 0a             ; serial      :    10
 00 00 0e 10             ; refresh     :  3600
 00 00 03 84             ; retry       :   900
 00 01 51 80             ; expire      : 86400
 00 00 00 3c             ; minimum     :    60
HEX_ANSWER_END

EXTRA_PACKET
HEX_ANSWER_BEGIN
 00 00 84 20             ; ID, Flags: QR, AA and AD ; 65535 -  4 = 65531
 00 00 00 01             ; QDCOUNT, ANCOUNT         ; 65531 -  4 = 65527
 00 00 00 00             ; NSCOUNT, ARCOUNT         ; 65527 -  4 = 65523

 00                      ; name        : .          ; 65523 -  1 = 65522
 00 40                   ; type        : SVCB       ; 65522 -  2 = 65520
 00 01                   ; class       : IN         ; 65520 -  2 = 65518
 00 00 00 00             ; TTL         :     0      ; 65518 -  4 = 65514
 ff e8                   ; RDLEN       : 65512      ; 65514 -  2 = 65512
 00 01                   ; priority    :     1      ; 65512 -  2 = 65510
 00                      ; target      : .          ; 65510 -  1 = 65509
''')
    fh.write(svcb_rdlength(65512, False))
    fh.write('''HEX_ANSWER_END

EXTRA_PACKET
HEX_ANSWER_BEGIN
 00 00 84 20             ; ID, Flags: QR, AA and AD
 00 00 00 01             ; QDCOUNT, ANCOUNT
 00 00 00 00             ; NSCOUNT, ARCOUNT

 06 76 69 63 74 69 6d 00 ; name        : victim.
 00 06                   ; type        : SOA
 00 01                   ; class       : IN
 00 00 01 2c             ; TTL         :   300
 00 16                   ; RDLEN       :    22
 00 00                   ; mname, rname: . .
 00 00 00 0a             ; serial      :    10
 00 00 0e 10             ; refresh     :  3600
 00 00 03 84             ; retry       :   900
 00 01 51 80             ; expire      : 86400
 00 00 00 3c             ; minimum     :    60
HEX_ANSWER_END
ENTRY_END
''')
