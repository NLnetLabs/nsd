/* simple program to test popen3 works as expected */
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
	int i, fds = 0;
	char buf[512], hdr[512];
	struct { FILE *fh; const char *str; } io[3] = {
		{ stdin, "stdin" }, { stdout, "stdout" }, { stderr, "stderr" }
	};

	(void)argc;
	(void)argv;

	hdr[0] = '\0';
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	for(i = 0; i < 3; i++) {
		char str[32];
		int fd = fileno(io[i].fh);
		assert(fd == i);
		if(fcntl(fd, F_GETFD) != -1) {
			fds |= (1<<fd);
		}
		(void)snprintf(str, sizeof(str), "%s%s%s", i == 0 ? "" : ",", (fds & (1<<fd)) ? "" : "!", io[i].str);
		memcpy(hdr + strlen(hdr), str, strlen(str) + 1);
	}

	if(fgets(buf, sizeof(buf), stdin) == NULL) {
		buf[0] = '\0';
	}
	if(fds & (1<<1)) {
		fprintf(stdout, "%s\n%s", hdr, buf);
	}
	if(fds & (1<<2)) {
		fprintf(stderr, "%s\n%s", hdr, buf);
	}

	return fds;
}

