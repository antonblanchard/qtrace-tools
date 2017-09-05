#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void sigtrap_handler(int signr, siginfo_t *info, void *unused)
{
	printf("SIGTRAP si_code 0x%x addr %p\n", info->si_code,
		info->si_addr);

#ifdef __powerpc__
	ucontext_t *ctx = unused;
	ctx->uc_mcontext.gp_regs[PT_NIP] += 4;
#endif
}

void main(void)
{
        struct sigaction action;

        memset(&action, 0, sizeof(action));
        action.sa_sigaction = sigtrap_handler;
        action.sa_flags = SA_SIGINFO;
        sigaction(SIGTRAP, &action, NULL);

	asm volatile("trap");

        exit(0);
}
