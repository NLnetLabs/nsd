/*
 * Like select(2) but set the signals to block while waiting in
 * select.  This version is not entirely race condition safe.  Only
 * operating system support can make it so.
 */

#include <config.h>

#include <sys/time.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <unistd.h>
#include <signal.h>

int
pselect (int n,
	 fd_set *readfds,
	 fd_set *writefds,
	 fd_set *exceptfds,
	 const struct timespec *timeout,
	 const sigset_t *sigmask)
{
	int result;
	sigset_t saved_sigmask;
	struct timespec saved_timeout;
	saved_timeout.ts_sec = timeout->ts_sec;
	saved_timeout.ts_usec = timeout->ts_usec;

	if (sigprocmask(SIG_SETMASK, sigmask, &saved_sigmask) == -1)
		return -1;

	rc = select(n, readfds, writefds, exceptfds, &saved_timeout);
	
	if (sigprocmask(SIG_SETMASK, saved_sigmask, NULL) == -1)
		return -1;

	return rc;
}
