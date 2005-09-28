;
; BIND data file for miek.nl for public use
;

$TTL    4D
$ORIGIN miek.nl.
@       IN      SOA     open.nlnetlabs.nl. miekg.atoom.net. (
                         2005061300         ; Serial
                             4H         ; Refresh
                             1H         ; Retry
                             7D         ; Expire
                             1D )       ; Negative Cache TTL
		IN	NS	open.nlnetlabs.nl.
		IN	NS	omval.tednet.nl.
		IN	NS	elektron.atoom.net.

		IN	MX	20 mail.atoom.net.
		IN	MX	20 sol.nlnetlabs.nl.

miek.nl.	IN	A	80.127.17.126
localhost	IN	A	127.0.0.1
a	    	IN	A	80.127.17.126
www     	IN 	CNAME 	a
