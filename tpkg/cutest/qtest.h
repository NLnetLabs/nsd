/* 
   qtest : test query answers
*/
#ifndef QTEST_H
#define QTEST_H
struct qtodo;
#include "buffer.h"

/* the query answer test.  The file format is a plain text file with:
# a list of qtodo entries:  (qnames must end with .)
query example.com. IN A
<text contents>
end_reply
query example.net. IN MX
no_reply  # for malformed
# perform check of answers against text output, 0 disabled
check 1
# and max number of speed iterations, 0 disabled
speed 1000
# write qfile.out with text answers, 0 disabled.
write 0
*/
struct qs {
	/* number of queries in list */
	int num;
	/* linked list of queries to perform */
	struct qtodo* qlist;
	/* last in qlist */
	struct qtodo* qlast;
	/* number of speed iterations */
	int speed;
	/* should check be performed or not */
	int check;
	/* should qfile.out be written */
	int write;
	/* size of qbuffer to allow (512 for UDP, 65535 for TCP) */
	int bufsize;
};

/* a query to do and its answer */
struct qtodo {
	/* next in list */
	struct qtodo* next;
	/* query in text */
	char* title;
	/* query to perform */
	buffer_type* q;
	/* answer in text format */
	char* txt;
};

/* run the qtest */
int runqtest(char* config, char* qfile, int verbose);

#endif /* QTEST_H */
