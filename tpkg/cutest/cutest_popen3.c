#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>

#include "config.h"
#include "popen3.h"

#include "tpkg/cutest/cutest.h"

#define use_stdin(x) (x & (1<<0))
#define use_stdout(x) (x & (1<<1))
#define use_stderr(x) (x & (1<<2))

static int popen3_echo(const char *str, int fds)
{
	int ret, wret, wstatus, status;
	int fdin, fdout, fderr;
	int *fdinptr, *fdoutptr, *fderrptr;
	char *cmd[] = { NULL, NULL };
	pid_t pid;
	char *buf = NULL;
	size_t len, size = 128;
	ssize_t got = -1;
	char *new_ln = NULL;

	ret = -1;
	fdin = fdout = fderr = -1;
	fdinptr = (use_stdin(fds) ? &fdin : NULL);
	fdoutptr = (use_stdout(fds) ? &fdout : NULL);
	fderrptr = (use_stderr(fds) ? &fderr : NULL);

	if((cmd[0] = getenv("POPEN3_ECHO")) == NULL) {
		cmd[0] = "./popen3_echo";
	}

	if((len = strlen(str)) > size) {
		size = len;
	}

	if((buf = malloc(size + 1)) == NULL) {
		fprintf(stderr, "%s: malloc: %s\n", __func__, strerror(errno));
		goto bail;
	}

	if((pid = popen3(cmd, fdinptr, fdoutptr, fderrptr)) == -1) {
		fprintf(stderr, "%s: popen3: %s\n", __func__, strerror(errno));
		goto bail;
	}

	if((use_stdin(fds) && fdin == -1) ||
	   (use_stdout(fds) && fdout == -1) ||
	   (use_stderr(fds) && fderr == -1))
	{
		fprintf(stderr, "%s: Opened pipes do not match requested\n", __func__);
		goto bail;
	}

	if(use_stdin(fds)) {
		if (write(fdin, str, len) == -1) {
			fprintf(stderr, "%s: write: %s\n", __func__, strerror(errno));
			goto bail;
		}
	}
	/* wait for popen3_echo to terminate */

	if((wret = waitpid(pid, &wstatus, 0)) == -1) {
		fprintf(stderr, "%s: waitpid: %s\n", __func__, strerror(errno));
		goto bail;
	} else if (wret == pid) {
		if(WIFEXITED(wstatus)) {
			status = WEXITSTATUS(wstatus);
		} else {
			fprintf(stderr, "%s: Subprocess exited abnormally\n", __func__);
			goto bail;
		}
	} else { /* should not happen */
		fprintf(stderr, "%s: waitpid: Unknown error\n", __func__);
		goto bail;
	}

	if(status != fds) {
		fprintf(stderr, "%s: Unexpected exit code\n", __func__);
		goto bail;
	}

	if(use_stdout(fds)) {
		if ((got = read(fdout, buf, size)) == -1) {
			fprintf(stderr, "%s: read: %s\n", __func__, strerror(errno));
			goto bail;
		}
		assert(got <= (ssize_t)size);
		buf[got] = 0;
		if (!(new_ln = strchr(buf, '\n'))) {
			fprintf(stderr, "%s: Could not read header from stdout\n", __func__);
			goto bail;
		}
		new_ln += 1;
		if ((got - (new_ln - buf)) != (int)len || strncmp(new_ln, str, len) != 0) {
			fprintf(stderr, "%s: Output on stdout did not match input\n", __func__);
			goto bail;
		}
	}

	if(use_stderr(fds)) {
		if ((got = read(fderr, buf, size)) == -1) {
			fprintf(stderr, "%s: read: %s\n", __func__, strerror(errno));
			goto bail;
		}
		assert(got <= (ssize_t)size);
		buf[got] = 0;
		if (!(new_ln = strchr(buf, '\n'))) {
			fprintf(stderr, "%s: Could not read header from stderr\n", __func__);
			goto bail;
		}
		new_ln += 1;
		if ((got - (new_ln - buf)) != (int)len || strncmp(new_ln, str, len) != 0) {
			fprintf(stderr, "%s: Output on stderr did not match input\n", __func__);
			goto bail;
		}
	}

	ret = 0;
bail:
	if(buf != NULL) {
		free(buf);
	}
	if(fdin != -1) {
		close(fdin);
	}
	if(fdout != -1) {
		close(fdout);
	}
	if(fderr != -1) {
		close(fderr);
	}
	return ret;
}

static void popen3_non_existing(CuTest *tc)
{
	char *command[] = { "./foobarbaz", NULL };
	int fin, fout, ferr;
	pid_t pid;

	fin = fout = ferr = -1;

	pid = popen3(command, &fin, &fout, &ferr);
	CuAssert(tc, "", pid == -1);
	CuAssert(tc, "", fin == -1);
	CuAssert(tc, "", fout == -1);
	CuAssert(tc, "", ferr == -1);
}

static void popen3_all_opened(CuTest *tc)
{
	int fds = (1<<0) + (1<<1) + (1<<2); /* stdin, stdout and stderr */
	const char str[] = "foobarbaz\n";
        CuAssert(tc, "", popen3_echo(str, fds) == 0);
}

static void popen3_all_closed(CuTest *tc)
{
	int fds = 0;
	const char str[] = "foobarbaz\n";
	CuAssert(tc, "", popen3_echo(str, fds) == 0);
}

static void popen3_stdin_only(CuTest *tc)
{
	int fds = (1<<0);
	const char str[] = "foobarbaz\n";
	CuAssert(tc, "", popen3_echo(str, fds) == 0);
}

static void popen3_stdout_only(CuTest *tc)
{
	int fds = (1<<0) + (1<<1);
	const char str[] = "foobarbaz\n";
	CuAssert(tc, "", popen3_echo(str, fds) == 0);
}

static void popen3_stderr_only(CuTest *tc)
{
	int fds = (1<<0) + (1<<2);
	const char str[] = "foobarbaz\n";
	CuAssert(tc, "", popen3_echo(str, fds) == 0);
}

CuSuite *reg_cutest_popen3(void)
{
	CuSuite *suite = CuSuiteNew();
	SUITE_ADD_TEST(suite, popen3_non_existing);
	SUITE_ADD_TEST(suite, popen3_all_opened);
	SUITE_ADD_TEST(suite, popen3_all_closed);
	SUITE_ADD_TEST(suite, popen3_stdin_only);
	SUITE_ADD_TEST(suite, popen3_stdout_only);
	SUITE_ADD_TEST(suite, popen3_stderr_only);
	return suite;
}

