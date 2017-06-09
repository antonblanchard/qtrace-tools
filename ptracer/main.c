#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/ptrace.h>

#include "pids.h"
#include "ptrace.h"
#include "perf_events.h"
#include "single_step.h"
#include "qtrace.h"
#include "ascii.h"
#include "ppc_storage.h"

#define NR_FILES (16*1024)

/*
 * We want to trace an active thread in the process. When attaching to a
 * process, count instructions in all threads and trace the one that hits
 * the below count first.
 */
#define FAST_FORWARD_COUNT 1000000

/* We catch all exits via ptrace, no need to be notified a second time. */
static void ignore_sigchld(void)
{
	struct sigaction sa = { .sa_handler = SIG_IGN };

	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("ignore_sigchld: sigaction");
		exit(1);
	}
}

/*
 * When fast forwarding with perf events, we need a file descriptor per
 * thread. Bump our open file limit.
 */
static void setrlimit_open_files(void)
{
	struct rlimit old_rlim, new_rlim;
	int new = NR_FILES;

	getrlimit(RLIMIT_NOFILE, &old_rlim);

	if (old_rlim.rlim_cur > new)
		return;

	while (1) {
		new_rlim.rlim_cur = new;
		new_rlim.rlim_max = old_rlim.rlim_max;

		if (setrlimit(RLIMIT_NOFILE, &new_rlim) == 0)
			break;

		new /= 2;
	}
}

static char *ascii_logfile = NULL;
static char *qtrace_logfile = NULL;
static unsigned long nr_insns_skip = 0;
static unsigned long nr_insns_left = -1UL;

static void print_insn(pid_t pid, uint32_t *pc)
{
	uint32_t insn;

	if (nr_insns_skip) {
		nr_insns_skip--;
		return;
	}

	insn = read_insn(pid, pc);

	if (nr_insns_left != -1) {
		if (nr_insns_left == 0)
			return;

		nr_insns_left--;
	}

	if (ascii_logfile)
		ascii_add_record(pid, insn, pc);

	if (qtrace_logfile) {
		int ret;
		struct pt_regs regs;
		unsigned long addr = 0, size = 0;

		ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		if (ret) {
			perror("print_insn: ptrace(PTRACE_GETREGS)");
			exit(1);
		}

		if (is_storage_insn(insn, &regs.gpr[0], &addr, &size))
			qtrace_add_storage_record(insn, pc, addr, size);
		else
			qtrace_add_record(insn, pc);
	}
}

void usage(void)
{
	fprintf(stderr, "Usage: ptracer [OPTION] PROG [ARGS]\n");
	fprintf(stderr, "\t-a logfile	ASCII disassembly to file\n");
	fprintf(stderr, "\t-q logfile	QTRACE output to file\n");
	fprintf(stderr, "\t-p pid	pid to attach to\n");
	fprintf(stderr, "\t-n nr_insns	Number of instructions to trace\n");
	fprintf(stderr, "\t-s nr_insns	Number of instructions to skip\n");
}

int main(int argc, char *argv[])
{
	pid_t tracing_pid;
	pid_t child_pid = 0;
#if 0
	bool follow_fork = false;
#endif

	while (1) {
		signed char c = getopt(argc, argv, "+a:q:p:fn:s:h");
		if (c < 0)
			break;

		switch (c) {
		case 'a':
			ascii_logfile = optarg;
			break;

		case 'q':
			qtrace_logfile = optarg;
			break;

		case 'p':
			child_pid = atoi(optarg);
			break;
#if 0
		case 'f':
			follow_fork = true;
			break;
#endif

		case 'n':
			nr_insns_left = strtol(optarg, NULL, 10);
			break;

		case 's':
			nr_insns_skip = strtol(optarg, NULL, 10);
			break;

		default:
			usage();
			exit(1);
		}
	}

	if ((child_pid && (argc - optind))) {
		usage();
		exit(1);
	}

	if (!child_pid && !(argc - optind)) {
		usage();
		exit(1);
	}

	if (!ascii_logfile && !qtrace_logfile) {
		ascii_logfile = "-";
		ascii_fout = stdout;
	} else {
		if (qtrace_logfile)
			qtrace_open(qtrace_logfile);

		if (ascii_logfile)
			ascii_open(ascii_logfile);
	}

	ignore_sigchld();

	setrlimit_open_files();

	if (child_pid) {
		capture_all_threads(child_pid);

		if (!nr_insns_skip)
			nr_insns_skip = FAST_FORWARD_COUNT;
	} else {
		tracing_pid = do_exec(&argv[optind]);
	}

	if (nr_insns_skip)
		tracing_pid = fast_forward(&nr_insns_skip);

	if (child_pid)
		release_all_non_tracing_threads(tracing_pid);

	if (ptrace(PTRACE_SINGLESTEP, tracing_pid, 0, 0) == -1) {
		perror("ptrace");
		exit(1);
	}

	while (1) {
		pid_t pid;
		int status;
		uint32_t *pc;
		uint32_t insn;
		unsigned long data;
		unsigned long ptrace_continue;

		while ((pid = waitpid(-1, &status, __WALL)) == -1) {
			if (errno != EINTR) {
				perror("main: waitpid");
				exit(1);
			}
		}

		if (!WIFSTOPPED(status)) {
			fprintf(stderr, "Unknown issue, waitpid returned 0x%x\n", status);
			exit(1);
		}

		ptrace_continue = PTRACE_CONT;
		if (pid == tracing_pid)
			ptrace_continue = PTRACE_SINGLESTEP;

		if (((status >> 16) == PTRACE_EVENT_CLONE) ||
		    ((status >> 16) == PTRACE_EVENT_VFORK) ||
		    ((status >> 16) == PTRACE_EVENT_FORK)) {
			if (ptrace(PTRACE_GETEVENTMSG, pid, NULL,
				   &data) == -1) {
				perror("main: ptrace(PTRACE_GETEVENTMSG");
				exit(1);
			}

			add_pid(data);

			if (ptrace(ptrace_continue, pid, 0, 0) == -1) {
				perror("main: ptrace(PTRACE_CONT)");
				exit(1);
			}

			continue;
		}

		if (((status >> 16) == PTRACE_EVENT_EXIT)) {
			remove_pid(pid);

			if (pid == tracing_pid) {
				qtrace_close();
				exit(0);
			}

			if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
				perror("main: ptrace(PTRACE_CONT)");
				exit(1);
			}

			continue;
		}

		/*
		 * We might see a stray SIGSTKFLT from an earlier fast forward.
		 * Just ignore it.
		 */
		if (WSTOPSIG(status) == SIGSTKFLT) {
			if (ptrace(ptrace_continue, pid, 0, 0) == -1) {
				perror("main: ptrace(PTRACE_CONT)");
				exit(1);
			}

			continue;
		}

		if (pid != tracing_pid) {
			unsigned int sig = WSTOPSIG(status);
			/*
			 * We assume this is a non tracing thread hitting our
			 * software breakpoint in the single step code.
			 *
			 * If the application is using software breakpoints,
			 * unfortunately this will break them.
			 */
			if (sig == SIGTRAP)
				sig = 0;

			if (ptrace(PTRACE_CONT, pid, 0, sig) == -1) {
				perror("main: ptrace(PTRACE_CONT)");
				exit(1);
			}

			continue;
		}

		/* XXX FIXME: need to handle exec in some sane way */

		pc = read_pc(pid);
		insn = read_insn(pid, pc);
		asm volatile("":::"memory");

		if (is_larx(insn)) {
			step_over_atomic(pid, pc, print_insn);
		} else {
			unsigned int sig = WSTOPSIG(status);

			if (sig == SIGTRAP)
				sig = 0;

			print_insn(pid, pc);

			if (nr_insns_left == 0) {
				detach_all_threads();
				exit(0);
			}

			if (ptrace(PTRACE_SINGLESTEP, pid, 0, sig) == -1) {
				perror("ptrace");
				exit(1);
			}
		}
	}

	return 0;
}
