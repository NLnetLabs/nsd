# run soms test for zonec

all: ../../zonec
	../../zonec -v -f test.db test.conf

soa: ../../zonec
	../../zonec -v -f test.db soa.conf

unknown: ../../zonec
	../../zonec -v -f test.db unknown.conf

dnssec: ../../zonec
	../../zonec -v -f test.db dnssec.conf
miek:
	../../zonec -v -f test.db miek.conf

nsd:	../../nsd
	@echo Running NSD on port 5353 with test.db 
	../../nsd -d -p 5353 -f test.db -u `whoami`
