# You may want to change the locations of the tools listed
ZONEC=~/cvs/nsd/zonec
NSD=~/cvs/nsd/nsd
MKVALID=~/cvs/nsd/test/bin/mkvalid
STRIPDIG=~/cvs/nsd/test/bin/stripdig.pl
QUERY=~/cvs/nsd/test/bin/query

# run on this port and under the current user
NSDOPT=-p 5353 -u `whoami`
## No serviceble parts below ##

.PHONY: nsd valid test stop diffclean currentclean

# you need to run make valid seperately
all:	QUESTIONS nsd test

nsd:
	@echo Running NSD on port 5353 with test.db 
	${NSD} ${NSDOPT} -f test.db

test.db:	conf
	${ZONEC} -f test.db conf

valid:		QUESTIONS
	@echo Generating valid answers...please verify
	${MKVALID} -s ${STRIPDIG} QUESTIONS

test:		QUESTIONS 
	@echo Sending queries to the nameserver...
	${QUERY} -s ${STRIPDIG} QUESTIONS

stop:	
	@echo Stopping all named instances
	killall nsd

diffclean:
	@echo Cleaning up .diff files
	rm -f *.diff

currentclean:
	@echo Cleaning up .current files
	rm -f *.current
