#include "config.h"

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(USE_MINI_EVENT)
# include "mini_event.h"
#elif defined(HAVE_EVENT_H)
# include <event.h>
#else
# include <event2/event.h>
# include <event2/event_struct.h>
# include <event2/event_compat.h>
#endif /* USE_MINI_EVENT */

#include "nsd.h"
#include "tpkg/cutest/cutest.h"

struct proc {
	pid_t pid;
	int wstatus;
	int fdin;
	int fdout;
	struct event event;
	short events;
};

#define NUM_CHILDREN (3)

struct testvars {
	struct event_base *event_base;
	struct event event_sigchld;
	struct proc agent;
	struct proc children[NUM_CHILDREN];
	unsigned int sigchld_count;
};

static void
child(int fdin, int fdout)
{
	char buf[32];
	ssize_t cnt;
	ssize_t discard;

	/* FIXME: maybe necessary to register signal handler? */
	discard = read(fdin, buf, sizeof(buf));
	(void)discard;
	cnt = snprintf(buf, sizeof(buf), "%d\n", getpid());
	discard = write(fdout, buf, (size_t)(cnt >= 0 ? cnt : 0));
	(void)discard;
	exit(0);
}

static void
sigterm_handler(int signo)
{
	(void)signo;
	exit(0);
}

static void
agent(int fdin, int fdout, struct testvars *vars, void(*func)(struct proc *))
{
	char buf[32];
	ssize_t cnt;
	ssize_t discard;

	signal(SIGTERM, sigterm_handler);
	discard = read(fdin, buf, sizeof(buf));
	(void)discard;
	for (size_t i = 0; i < NUM_CHILDREN; i++) {
		func(&vars->children[i]);
	}
	cnt = snprintf(buf, sizeof(buf), "%d\n", getpid());
	discard = write(fdout, buf, (size_t)(cnt >= 0 ? cnt : 0));
	(void)discard;
	exit(0);
}

static void
agent_callback(int fd, short event, void *arg)
{
	char buf[] = "x";
	struct proc *proc = (struct proc *)arg;
	ssize_t discard;

	(void)fd;
	assert(arg != NULL);

	if (event & EV_TIMEOUT) {
		discard = write(fd, buf, strlen(buf));
		(void)discard;
	} else if(event & EV_WRITE) {
		discard = write(fd, buf, strlen(buf));
		(void)discard;
		proc->events |= EV_WRITE;
	}
}

static void
child_callback(int fd, short event, void *arg)
{
	struct proc *proc = (struct proc *)arg;

	(void)fd;
	assert(arg != NULL);

	if (event & EV_READ) {
		proc->events |= EV_READ;
	}
}

static void
sigchld_callback(int sig, short event, void *arg)
{
	pid_t pid;
	int wstatus = 0;
	struct testvars *vars = (struct testvars *)arg;
	struct proc *proc;

	assert(sig == SIGCHLD);
	assert(event & EV_SIGNAL);
	assert(arg != NULL);

	do {
		pid = waitpid(-1, &wstatus, WNOHANG);
		proc = NULL;
		if(vars->agent.pid == pid) {
			proc = &vars->agent;
		} else if(pid > 0) {
			for(int i = 0; i < NUM_CHILDREN; i++) {
				if(vars->children[i].pid == pid) {
					proc = &vars->children[i];
				}
			}
		}
		if(proc != NULL) {
			vars->sigchld_count++;
			proc->wstatus = wstatus;
			proc->events |= EV_SIGNAL;
		}
	} while((pid == -1 && errno == EINTR) || (pid > 0));

	if(vars->sigchld_count == (NUM_CHILDREN + 1)) {
		event_base_loopexit(vars->event_base, NULL);
	}
}

static void
fork_children(struct testvars *vars)
{
	for(int i = 0; i < NUM_CHILDREN; i++) {
		pid_t pid;
		int ret, fdin[2], fdout[2];
		ret = pipe(fdin);
		assert(ret == 0);
		ret = pipe(fdout);
		assert(ret == 0);
		if((pid = fork()) == 0) {
			close(fdin[1]);
			close(fdout[0]);
			child(fdin[0], fdout[1]);
			/* never reached */
		}
		close(fdin[0]);
		close(fdout[1]);
		vars->children[i].pid = pid;
		vars->children[i].fdin = fdin[1];
		vars->children[i].fdout = fdout[0];
		event_set(
			&vars->children[i].event,
			 vars->children[i].fdin,
			 EV_READ,
			&child_callback,
			&vars->children[i]);
		event_base_set(vars->event_base, &vars->children[i].event);
		event_add(&vars->children[i].event, NULL);
	}
}

static void
fork_agent(struct testvars *vars, void(*func)(struct proc *))
{
	pid_t pid;
	int ret, fdin[2], fdout[2];
	struct timeval timeout = { 1, 0 };
	ret = pipe(fdin);
	assert(ret == 0);
	ret = pipe(fdout);
	assert(ret == 0);
	if((pid = fork()) == 0) {
		close(fdin[1]);
		close(fdout[0]);
		agent(fdin[0], fdout[1], vars, func);
		/* never reached */
	}
	close(fdin[0]);
	close(fdout[1]);
	vars->agent.pid = pid;
	vars->agent.fdin = fdin[1];
	vars->agent.fdout = fdout[0];
	event_set(
		&vars->agent.event,
		 vars->agent.fdin,
		 EV_WRITE,
		&agent_callback,
		 vars);
	event_base_set(vars->event_base, &vars->agent.event);
	event_add(&vars->agent.event, &timeout);
}

static void
event_setup(struct testvars *vars)
{
	int ret;

	memset(vars, 0, sizeof(*vars));
	vars->event_base = nsd_child_event_base();
	assert(vars->event_base != NULL);
	event_set(&vars->event_sigchld, SIGCHLD, EV_SIGNAL | EV_PERSIST, sigchld_callback, vars);
	ret = event_base_set(vars->event_base, &vars->event_sigchld);
	assert(ret == 0);
	ret = event_add(&vars->event_sigchld, NULL);
	assert(ret == 0);

	for(int i = 0; i < NUM_CHILDREN; i++) {
		vars->children[i].pid = -1;
		vars->children[i].fdin = -1;
		vars->children[i].fdout = -1;
		memset(&vars->children[i].event, 0, sizeof(vars->children[i].event));
	}
}

static void
event_teardown(struct testvars *vars)
{
	if(vars->agent.fdin != -1 &&
	   event_initialized(&vars->agent.event) &&
	   event_get_fd(&vars->agent.event) == vars->agent.fdin)
	{
		event_del(&vars->agent.event);
	}

	for(int i = 0; i < NUM_CHILDREN; i++) {
		if(vars->children[i].fdin != -1 &&
		   vars->children[i].event.ev_fd == vars->children[i].fdin)
		{
			event_del(&vars->children[i].event);
		}
	}

	event_del(&vars->event_sigchld);
	event_base_free(vars->event_base);

	(void)vars;
}

static void
stop_child(struct proc *proc)
{
	char buf[] = "x";
	ssize_t discard;
	discard = write(proc->fdin, buf, strlen(buf));
	(void)discard;
}

static void
terminate_child(struct proc *proc)
{
	kill(proc->pid, SIGTERM);
}

static void
kill_child(struct proc *proc)
{
	kill(proc->pid, SIGKILL);
}

static void
event_wait_for_children(CuTest *tc)
{
	int ret;
	struct testvars vars;

	event_setup(&vars);

	fork_children(&vars);
	fork_agent(&vars, stop_child);
	ret = event_base_dispatch(vars.event_base);

	CuAssert(tc, "", ret != -1);

	for(int i = 0; i < NUM_CHILDREN; i++) {
		CuAssert(tc, "", WIFEXITED(vars.children[i].wstatus));
		CuAssert(tc, "", (vars.children[i].events & EV_SIGNAL));
	}

	event_teardown(&vars);
}

static void
event_terminate_children(CuTest *tc)
{
	int ret;
	struct testvars vars;

	event_setup(&vars);

	fork_children(&vars);
	fork_agent(&vars, terminate_child);
	ret = event_base_dispatch(vars.event_base);

	CuAssert(tc, "", ret != -1);

	for(int i = 0; i < NUM_CHILDREN; i++) {
		CuAssert(tc, "", !WIFEXITED(vars.children[i].wstatus));
		CuAssert(tc, "", (vars.children[i].events & EV_SIGNAL));
	}

	event_teardown(&vars);
}

static void
event_kill_children(CuTest *tc)
{
	int ret;
	struct testvars vars;

	event_setup(&vars);

	fork_children(&vars);
	fork_agent(&vars, kill_child);
	ret = event_base_dispatch(vars.event_base);

	CuAssert(tc, "", ret != -1);

	for(int i = 0; i < NUM_CHILDREN; i++) {
		CuAssert(tc, "", !WIFEXITED(vars.children[i].wstatus));
		CuAssert(tc, "", (vars.children[i].events & EV_SIGNAL));
	}

	event_teardown(&vars);
}

CuSuite *reg_cutest_event(void)
{
	CuSuite *suite = CuSuiteNew();
	SUITE_ADD_TEST(suite, &event_wait_for_children);
	SUITE_ADD_TEST(suite, &event_terminate_children);
	SUITE_ADD_TEST(suite, &event_kill_children);
	return suite;
}
