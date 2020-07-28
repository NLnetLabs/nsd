#!
# premade query answers
# $ORIGIN example.com. 
$TTL 3600

# reply to questions
ENTRY_BEGIN
MATCH qtype
REPLY QUERY NOERROR
ADJUST copy_id
SECTION QUESTION
@ IN IXFR
SECTION ANSWER
@ 345600 IN SOA ns0.example.org. root 1 1 1 1 1
@ 345600 IN SOA ns0.example.org. root 1 1 1 1 1
ENTRY_END
