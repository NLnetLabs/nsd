# Makefile for testing NSD
.PHONY: all test clean

PORT=5053

all: test

test: test.zone.db
	@echo -n "Starting nsd..."
	@../../nsd -p $(PORT) -f test.zone.db
	@echo "done."
	@echo "Start test..."
	@./q.sh $(PORT)
	@echo "Killing test invocation of nsd"
	@../../nsdc.sh stop


test.zone.db: zone-list
	@../../zonec -f test.zone.db zone-list

clean:
	@rm -f test.zone.db
	@rm -f answers*
	@rm -f diff*
