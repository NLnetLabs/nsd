# run soms test for zonec2

all-test: ../../zonec2
	../../zonec2 -p -v -f test.db test.conf

soa-test: ../../zonec2
	../../zonec2 -p -v -f test.db soa.conf

unknown-test: ../../zonec2
	../../zonec2 -p -v -f test.db unknown.conf

u-test:	unknown-test
