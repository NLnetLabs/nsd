example.com.	3441	IN	SOA	ns.icann.org. noc.dns.icann.org. 2021052033 7200 3600 1209600 3600
www.example.com.	86400	IN	AAAA	2606:2800:220:1:248:1893:25c8:1946
www.example.com.	43200	IN	TXT	"v=spf1 -all"
www.example.com.	15294	IN	A	93.184.216.34
example.com.	43200	IN	AAAA	2606:2800:220:1:248:1893:25c8:1946
example.com.	86400	IN	TXT	"8j5nfqld20zpcyr8xjw0ydcfq9rk8hgm"
example.com.	86400	IN	TXT	"v=spf1 -all"
example.com.	43200	IN	MX	0 .
example.com.	86400	IN	NS	a.iana-servers.net.
example.com.	86400	IN	NS	b.iana-servers.net.
example.com.	4354	IN	A	93.184.216.34
