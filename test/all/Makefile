ZONEC=~/cvs/nsd/zonec
NSD=~/cvs/nsd/nsd
NSDOPT=-p 5353 -u `whoami`
MKVALID=./mkvalid
QUERY=./query

.PHONY: nsd valid

# you need to run make valid seperately
all:	QUESTIONS nsd test

nsd:
	@echo Running NSD on port 5353 with test.db 
	${NSD} ${NSDOPT} -f test.db

test.db:	conf
	${ZONEC} -f test.db conf

valid:		QUESTIONS
	@echo Generating valid answers...please verify
	${MKVALID} QUESTIONS

test:		QUESTIONS 
	@echo Sending queries to the nameserver...
	${QUERY} QUESTIONS
