;
; BIND data file for miek.nl for internal use
;
$TTL    1H
@       IN      SOA     elektron.atoom.net. miekg.atoom.net. (
                     2002120700         ; Serial
                             6H         ; Refresh
                             2H         ; Retry
                             7D         ; Expire
                             1H )       ; Negative Cache TTL

@       IN      NS      elektron.atoom.net.
@	IN	MX	10 elektron.atoom.net.
@	IN	DS	12345 3 1 123456789abcdef67890123456789abcdef67890
