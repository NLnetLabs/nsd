# run soms test for zonec

all-test: ../../zonec
	../../zonec -p -v -f test.db test.conf

soa-test: ../../zonec
	../../zonec -p -v -f test.db soa.conf

unknown-test: ../../zonec
	../../zonec -p -v -f test.db unknown.conf

u-test:	unknown-test
