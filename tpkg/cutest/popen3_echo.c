/* simple program to test popen3 works as expected */
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	int fl, fd, fds = 0;
	char buf[512];

	(void)argc;
	(void)argv;

	buf[0] = '\0';
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	fd = fileno(stdin);
	if (fcntl(fd, F_GETFL) != -1)
		fds |= 1;
	fd = fileno(stdout);
	if ((fl = fcntl(fd, F_GETFL)) != -1 && (fl & (O_WRONLY | O_RDWR)))
		fds |= 2;
	fd = fileno(stderr);
	if ((fl = fcntl(fd, F_GETFL)) != -1 && (fl & (O_WRONLY | O_RDWR)))
		fds |= 4;

	if (fds & 1)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result" 
		fgets(buf, sizeof(buf), stdin);
#pragma GCC diagnostic pop 
	if ((fds & 3) == 3)
		fprintf(stdout, "%sstdin,stdout,stderr\n%s", (fds & 1) ? "" : "!", buf);
	if ((fds & 5) == 5)
		fprintf(stderr, "%sstdin,stdout,stderr\n%s", (fds & 1) ? "" : "!", buf);

	exit(fds);
}
