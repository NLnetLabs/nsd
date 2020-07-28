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
	int event_added;
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

/** verbosity for test to tell what is going on */
static int verb = 0;

static void
child(int fdin, int fdout)
{
	char buf[32];
	ssize_t cnt;
	ssize_t discard;

	if(verb) log_msg(LOG_INFO, "child start\n");
	/* FIXME: maybe necessary to register signal handler? */
	discard = read(fdin, buf, sizeof(buf));
	(void)discard;
	cnt = snprintf(buf, sizeof(buf), "%d\n", getpid());
	discard = write(fdout, buf, (size_t)(cnt >= 0 ? cnt : 0));
	(void)discard;
	if(verb) log_msg(LOG_INFO, "child end\n");
	exit(0);
}

static void
sigterm_handler(int signo)
{
	if(verb) log_msg(LOG_INFO, "sigterm_handler\n");
	(void)signo;
	exit(0);
}

static void
agent(int fdin, int fdout, struct testvars *vars, void(*func)(struct proc *))
{
	char buf[32];
	size_t i;
	ssize_t cnt;
	ssize_t discard;

	if(verb) log_msg(LOG_INFO, "agent start\n");
	signal(SIGTERM, sigterm_handler);
	discard = read(fdin, buf, sizeof(buf));
	(void)discard;
	for (i = 0; i < NUM_CHILDREN; i++) {
		func(&vars->children[i]);
	}
	cnt = snprintf(buf, sizeof(buf), "%d\n", getpid());
	discard = write(fdout, buf, (size_t)(cnt >= 0 ? cnt : 0));
	(void)discard;
	if(verb) log_msg(LOG_INFO, "agent end\n");
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
		if(verb) log_msg(LOG_INFO, "agent_callback: timeout\n");
		discard = write(fd, buf, strlen(buf));
		(void)discard;
	} else if(event & EV_WRITE) {
		if(verb) log_msg(LOG_INFO, "agent_callback: write\n");
		discard = write(fd, buf, strlen(buf));
		(void)discard;
		proc->events |= EV_WRITE;
	} else {
		if(verb) log_msg(LOG_INFO, "agent_callback: other\n");
	}
}

static void
child_callback(int fd, short event, void *arg)
{
	struct proc *proc = (struct proc *)arg;

	(void)fd;
	assert(arg != NULL);
	if(verb && (proc->events&EV_READ) == 0)
		log_msg(LOG_INFO, "child_callback\n");

	if (event & EV_READ) {
		proc->events |= EV_READ;
	}
}

static void
sigchld_callback(int sig, short event, void *arg)
{
	pid_t pid;
	int i, wstatus = 0;
	struct testvars *vars = (struct testvars *)arg;
	struct proc *proc;

	assert(sig == SIGCHLD);
	assert(event & EV_SIGNAL);
	assert(arg != NULL);
	if(verb) log_msg(LOG_INFO, "sigchld_callback\n");

	do {
		pid = waitpid(-1, &wstatus, WNOHANG);
		proc = NULL;
		if(vars->agent.pid == pid) {
			proc = &vars->agent;
			if(verb) log_msg(LOG_INFO, "sigchld_callback: agent exited\n");
		} else if(pid > 0) {
			for(i = 0; i < NUM_CHILDREN; i++) {
				if(vars->children[i].pid == pid) {
					proc = &vars->children[i];
					if(verb) log_msg(LOG_INFO, "sigchld_callback: child %d exited\n", (int)i);
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
	int i;
	for(i = 0; i < NUM_CHILDREN; i++) {
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
	/* 0.1 second timeout, speeds up test compared to 1 second timeout */
	struct timeval timeout = { 0, 100000 };
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
		 EV_TIMEOUT,
		&agent_callback,
		 vars);
	event_base_set(vars->event_base, &vars->agent.event);
	event_add(&vars->agent.event, &timeout);
	vars->agent.event_added = 1;
}

static void
event_setup(struct testvars *vars)
{
	int i, ret;

	memset(vars, 0, sizeof(*vars));
	vars->event_base = nsd_child_event_base();
	assert(vars->event_base != NULL);
	event_set(&vars->event_sigchld, SIGCHLD, EV_SIGNAL | EV_PERSIST, sigchld_callback, vars);
	ret = event_base_set(vars->event_base, &vars->event_sigchld);
	assert(ret == 0);
	ret = signal_add(&vars->event_sigchld, NULL);
	assert(ret == 0);

	for(i = 0; i < NUM_CHILDREN; i++) {
		vars->children[i].pid = -1;
		vars->children[i].fdin = -1;
		vars->children[i].fdout = -1;
		memset(&vars->children[i].event, 0, sizeof(vars->children[i].event));
	}
}

static void
event_teardown(struct testvars *vars)
{
	int i;
	if(vars->agent.fdin != -1 &&
	   vars->agent.event_added &&
	   vars->agent.event.ev_fd == vars->agent.fdin)
	{
		event_del(&vars->agent.event);
	}

	for(i = 0; i < NUM_CHILDREN; i++) {
		if(vars->children[i].fdin != -1 &&
		   vars->children[i].event.ev_fd == vars->children[i].fdin)
		{
			event_del(&vars->children[i].event);
		}
	}

	signal_del(&vars->event_sigchld);
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
	int i, ret;
	struct testvars vars;

	if(verb) log_msg(LOG_INFO, "event_wait_for_children start\n");
	event_setup(&vars);

	fork_children(&vars);
	fork_agent(&vars, stop_child);
	ret = event_base_dispatch(vars.event_base);

	CuAssert(tc, "", ret != -1);

	for(i = 0; i < NUM_CHILDREN; i++) {
		CuAssert(tc, "", WIFEXITED(vars.children[i].wstatus));
		CuAssert(tc, "", (vars.children[i].events & EV_SIGNAL));
	}

	event_teardown(&vars);
	if(verb) log_msg(LOG_INFO, "event_wait_for_children end\n");
}

static void
event_terminate_children(CuTest *tc)
{
	int i, ret;
	struct testvars vars;

	if(verb) log_msg(LOG_INFO, "event_terminate_children start\n");
	event_setup(&vars);

	fork_children(&vars);
	fork_agent(&vars, terminate_child);
	ret = event_base_dispatch(vars.event_base);

	CuAssert(tc, "", ret != -1);

	for(i = 0; i < NUM_CHILDREN; i++) {
		CuAssert(tc, "", !WIFEXITED(vars.children[i].wstatus));
		CuAssert(tc, "", (vars.children[i].events & EV_SIGNAL));
	}

	event_teardown(&vars);
	if(verb) log_msg(LOG_INFO, "event_terminate_children end\n");
}

static void
event_kill_children(CuTest *tc)
{
	int i, ret;
	struct testvars vars;

	if(verb) log_msg(LOG_INFO, "event_kill_children start\n");
	event_setup(&vars);

	fork_children(&vars);
	fork_agent(&vars, kill_child);
	ret = event_base_dispatch(vars.event_base);

	CuAssert(tc, "", ret != -1);

	for(i = 0; i < NUM_CHILDREN; i++) {
		CuAssert(tc, "", !WIFEXITED(vars.children[i].wstatus));
		CuAssert(tc, "", (vars.children[i].events & EV_SIGNAL));
	}

	event_teardown(&vars);
	if(verb) log_msg(LOG_INFO, "event_kill_children end\n");
}

CuSuite *reg_cutest_event(void)
{
	CuSuite *suite = CuSuiteNew();
	verb = 0; /* local debug output verbosity */
	SUITE_ADD_TEST(suite, &event_wait_for_children);
	SUITE_ADD_TEST(suite, &event_terminate_children);
	SUITE_ADD_TEST(suite, &event_kill_children);
	return suite;
}
