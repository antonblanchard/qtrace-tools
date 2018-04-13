#define _GNU_SOURCE
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <linux/ptrace.h>

#include <qtwriter.h>

#include "../qtlib/branch.h"

static struct qtwriter_state qtwr;

#include "pids.h"
#include "ptrace.h"
#include "perf_events.h"
#include "single_step.h"
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

struct register_state {
	struct pt_regs regs;
	__int128 vmx_regs[32+2];
	__int128 vsx_regs[32];
	unsigned int fpscr;
};
static struct register_state prev_state;

static void do_checkpoint(pid_t pid, char *dir)
{
	char pidstr[8];

	snprintf(pidstr, sizeof(pidstr)-1, "%d", pid);

	if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1) {
		perror("do_checkpoint: ptrace(PTRACE_DETACH)");
		exit(1);
	}

	if (execlp("sudo", "sudo", "criu", "dump", "-j", "-s", "-t", pidstr,
		"-D", dir, NULL) == -1) {
		perror("do_checkpoint: execl");
	}

	if (qtrace_logfile)
		qtwriter_close(&qtwr);
	exit(0);
}

static void get_gp_regs(unsigned long pid, struct register_state *state)
{
	if (ptrace(PTRACE_GETREGS, pid, NULL, &state->regs)) {
		perror("get_gp_regs: ptrace(PTRACE_GETREGS)");
		exit(1);
	}
}

static void get_vmx_regs(unsigned long pid, struct register_state *state)
{
	if (ptrace(PTRACE_GETVRREGS, pid, NULL, &state->vmx_regs)) {
		perror("get_gp_regs: ptrace(PTRACE_GETREGS)");
		exit(1);
	}
}

static void get_vsx_regs(unsigned long pid, struct register_state *state)
{
	unsigned long i;
	unsigned long fpr[33];
	unsigned long vsx[32];

	if (ptrace(PTRACE_GETFPREGS, pid, NULL, &fpr)) {
		perror("get_gp_regs: ptrace(PTRACE_GETREGS)");
		exit(1);
	}

	if (ptrace(PTRACE_GETVSRREGS, pid, NULL, &vsx)) {
		perror("get_gp_regs: ptrace(PTRACE_GETREGS)");
		exit(1);
	}

	for (i = 0; i < 32; i++) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
		state->vsx_regs[i] = (((__int128)vsx[i]) << 64) | fpr[i];
#else
		state->vsx_regs[i] = (((__int128)fpr[i]) << 64) | vsx[i];
#endif
	}

	state->fpscr = fpr[32];
}

static void get_state(unsigned long pid, struct register_state *state)
{
	memset(state, 0xa5, sizeof(*state));

	get_gp_regs(pid, state);
	get_vmx_regs(pid, state);
	get_vsx_regs(pid, state);
}

static void compare32(uint32_t prev, uint32_t cur, char *str)
{
	if (prev != cur)
		fprintf(ascii_fout, "\t%s 0x%08x\n", str, cur);
}

static void compare64(uint64_t prev, uint64_t cur, char *str)
{
	if (prev != cur)
		fprintf(ascii_fout, "\t%s 0x%016lx\n", str, cur);
}

static void compare128(__int128 prev, __int128 cur, char *str)
{
	if (prev != cur) {
		fprintf(ascii_fout, "\t%s 0x%016lx%016lx\n", str,
			(unsigned long)(cur >> 64),
			(unsigned long)(cur & 0xffffffffffffffffUL));
	}
}

static void print_state(unsigned long pid)
{
	struct register_state cur_state;
	unsigned int i;
	char str[16];

	get_state(pid, &cur_state);

	for (i = 0; i < 32; i++) {
		sprintf(str, "GPR%02d", i);
		compare64(prev_state.regs.gpr[i], cur_state.regs.gpr[i], str);
	}

	for (i = 0; i < 32; i++) {
		sprintf(str, "VR%02d ", i);
		compare128(prev_state.vmx_regs[i], cur_state.vmx_regs[i], str);
	}

	compare32(prev_state.vmx_regs[32], cur_state.vmx_regs[32], "VSCR");

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	compare32(prev_state.vmx_regs[33], cur_state.vmx_regs[33], "VRSAVE");
#else
	compare32(prev_state.vmx_regs[33] >> 96, cur_state.vmx_regs[33] >> 96,
		"VRSAVE");
#endif

	for (i = 0; i < 32; i++) {
		sprintf(str, "VSR%02d", i);
		compare128(prev_state.vsx_regs[i], cur_state.vsx_regs[i], str);
	}

	compare64(prev_state.regs.ctr, cur_state.regs.ctr, "CTR");
	compare64(prev_state.regs.link, cur_state.regs.link, "LR");
	compare64(prev_state.regs.xer, cur_state.regs.xer, "XER");
	compare32(prev_state.regs.ccr, cur_state.regs.ccr, "CR");

	compare64(prev_state.fpscr, cur_state.fpscr, "FPSCR");

	memcpy(&prev_state, &cur_state, sizeof(struct register_state));
}

static bool register_dump;

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

	if (ascii_logfile) {
		if (register_dump)
			print_state(pid);

		ascii_add_record(pid, insn, pc);
	}

	if (qtrace_logfile) {
		struct qtrace_record qtr;
		int ret;
		struct pt_regs regs;
		unsigned long addr = 0, size = 0;

		ret = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
		if (ret) {
			perror("print_insn: ptrace(PTRACE_GETREGS)");
			exit(1);
		}

		memset(&qtr, 0, sizeof(qtr));
		qtr.insn = insn;
		qtr.insn_addr = (unsigned long)pc;

		if (is_storage_insn(insn, &regs.gpr[0], &addr, &size)) {
			qtr.data_addr = addr;
			qtr.data_addr_valid = true;
		}

		qtr.branch = is_branch(insn);
		qtr.conditional_branch = is_conditional_branch(insn);
		qtr.conditional_branch = true;

		if (qtwriter_write_record(&qtwr, &qtr) == false) {
			fprintf(stderr, "qtwriter_write_record failed\n");
			exit(1);
		}
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
	char *checkpoint_dir = NULL;
#if 0
	bool follow_fork = false;
#endif

	while (1) {
		signed char c = getopt(argc, argv, "+a:q:p:fn:s:rc:h");
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

		case 'r':
			register_dump = true;
			break;

		case 's':
			nr_insns_skip = strtol(optarg, NULL, 10);
			break;

		case 'c':
			checkpoint_dir = optarg;
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
			qtwriter_open(&qtwr, qtrace_logfile, 0);

		if (ascii_logfile)
			ascii_open(ascii_logfile);
	}

	ignore_sigchld();

	setrlimit_open_files();

	if (child_pid) {
		capture_all_threads(child_pid);

		tracing_pid = child_pid;

		if (!nr_insns_skip && (nr_pids > 1))
			nr_insns_skip = FAST_FORWARD_COUNT;
	} else {
		tracing_pid = do_exec(&argv[optind]);
	}

	if (nr_insns_skip)
		tracing_pid = fast_forward(&nr_insns_skip);

	if (checkpoint_dir)
		do_checkpoint(tracing_pid, checkpoint_dir);

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
				if (qtrace_logfile)
					qtwriter_close(&qtwr);
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
			 * We use an illegal instruction instead of a trap
			 * because the application might be using traps.
			 *
			 * Hopefully they aren't relying on getting SIGILL,
			 * because we eat them here.
			 */
			if (sig == SIGILL)
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

			/*
			 * It would be nice if ptrace had a
			 * PTRACE_O_SINGLESTEP/PTRACE_EVENT_SINGLESTEP option
			 * so we could work this out without another call.
			 */
			if (sig == SIGTRAP) {
				siginfo_t siginfo;

				if (ptrace(PTRACE_GETSIGINFO, pid, 0,
					   &siginfo) == -1) {
					perror("ptrace");
					exit(1);
				}

				if (siginfo.si_code == TRAP_TRACE) {
					sig = 0;
				}
			}

			print_insn(pid, pc);

			if (nr_insns_left == 0) {
				detach_all_threads();
				if (qtrace_logfile)
					qtwriter_close(&qtwr);
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
