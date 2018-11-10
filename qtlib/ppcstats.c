/*
 * Copyright (C) 2018 Michael Neuling <mikey@neuling.org>, IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>

struct exception {
	uint64_t addr;
	const char *name;
	uint64_t count;
};
struct exception exceptions[] = {
	/* Order roughly by likelyhood */
	{ 0xc00, "System Call"},
	{ 0x300, "Data Storage"},
	{ 0x900, "Decrementer"},
	{ 0x400, "Instruction Storage"},
	{ 0xf20, "Vector Unavailable"},
	{ 0xf40, "VSX Unavailable"},
	{ 0xf60, "Facility Unavailable"},
	{ 0x500, "External"},
	{ 0x100, "System Reset"},
	{ 0x200, "Machine Check"},
	{ 0x380, "Data Segment"},
	{ 0x480, "Instruction Segment"},
	{ 0x600, "Alignment"},
	{ 0x700, "Program"},
	{ 0x800, "Floating-Point Unavailable"},
	{ 0x980, "Hypervisor Decrementer"},
	{ 0xa00, "Directed Privileged Doorbell"},
	{ 0xb00, "0xB00 Reserved"},
	{ 0xd00, "Trace"},
	{ 0xe00, "Hypervisor Data Storage"},
	{ 0xe20, "Hypervisor Instruction Storage"},
	{ 0xe40, "Hypervisor Emulation Assistance"},
	{ 0xe60, "Hypervisor Maintenance"},
	{ 0xe80, "Directed Hypervisor Doorbell"},
	{ 0xea0, "Hypervisor Virtualization"},
	{ 0xec0, "0xec0 Reserved"},
	{ 0xee0, "0xee0 Reserved"},
	{ 0xf00, "Performance Monitor"},
	{ 0xf80, "Hypervisor Facility Unavailable"},
	{ 0xfa0, "0xfa0 Reserved"},
	{ 0xfc0, "0xfc0 Reserved"},
	{ 0xfe0, "0xfe0 Reserved"},
};
#define NR_EXCEPTIONS (sizeof(exceptions) / sizeof(struct exception))

struct call {
	char *name;
	uint64_t count;
};
/* mirror of arch/powerpc/include/uapi/asm/unistd.h */
struct call syscalls[] = {
	{ "restart_syscall" },      // 0
	{ "exit" },                 // 1
	{ "fork" },                 // 2
	{ "read" },                 // 3
	{ "write" },                // 4
	{ "open" },                 // 5
	{ "close" },                // 6
	{ "waitpid" },              // 7
	{ "creat" },                // 8
	{ "link" },                 // 9
	{ "unlink" },              // 10
	{ "execve" },              // 11
	{ "chdir" },               // 12
	{ "time" },                // 13
	{ "mknod" },               // 14
	{ "chmod" },               // 15
	{ "lchown" },              // 16
	{ "break" },               // 17
	{ "oldstat" },             // 18
	{ "lseek" },               // 19
	{ "getpid" },              // 20
	{ "mount" },               // 21
	{ "umount" },              // 22
	{ "setuid" },              // 23
	{ "getuid" },              // 24
	{ "stime" },               // 25
	{ "ptrace" },              // 26
	{ "alarm" },               // 27
	{ "oldfstat" },            // 28
	{ "pause" },               // 29
	{ "utime" },               // 30
	{ "stty" },                // 31
	{ "gtty" },                // 32
	{ "access" },              // 33
	{ "nice" },                // 34
	{ "ftime" },               // 35
	{ "sync" },                // 36
	{ "kill" },                // 37
	{ "rename" },              // 38
	{ "mkdir" },               // 39
	{ "rmdir" },               // 40
	{ "dup" },                 // 41
	{ "pipe" },                // 42
	{ "times" },               // 43
	{ "prof" },                // 44
	{ "brk" },                 // 45
	{ "setgid" },              // 46
	{ "getgid" },              // 47
	{ "signal" },              // 48
	{ "geteuid" },             // 49
	{ "getegid" },             // 50
	{ "acct" },                // 51
	{ "umount2" },             // 52
	{ "lock" },                // 53
	{ "ioctl" },               // 54
	{ "fcntl" },               // 55
	{ "mpx" },                 // 56
	{ "setpgid" },             // 57
	{ "ulimit" },              // 58
	{ "oldolduname" },         // 59
	{ "umask" },               // 60
	{ "chroot" },              // 61
	{ "ustat" },               // 62
	{ "dup2" },                // 63
	{ "getppid" },             // 64
	{ "getpgrp" },             // 65
	{ "setsid" },              // 66
	{ "sigaction" },           // 67
	{ "sgetmask" },            // 68
	{ "ssetmask" },            // 69
	{ "setreuid" },            // 70
	{ "setregid" },            // 71
	{ "sigsuspend" },          // 72
	{ "sigpending" },          // 73
	{ "sethostname" },         // 74
	{ "setrlimit" },           // 75
	{ "getrlimit" },           // 76
	{ "getrusage" },           // 77
	{ "gettimeofday" },        // 78
	{ "settimeofday" },        // 79
	{ "getgroups" },           // 80
	{ "setgroups" },           // 81
	{ "select" },              // 82
	{ "symlink" },             // 83
	{ "oldlstat" },            // 84
	{ "readlink" },            // 85
	{ "uselib" },              // 86
	{ "swapon" },              // 87
	{ "reboot" },              // 88
	{ "readdir" },             // 89
	{ "mmap" },                // 90
	{ "munmap" },              // 91
	{ "truncate" },            // 92
	{ "ftruncate" },           // 93
	{ "fchmod" },              // 94
	{ "fchown" },              // 95
	{ "getpriority" },         // 96
	{ "setpriority" },         // 97
	{ "profil" },              // 98
	{ "statfs" },              // 99
	{ "fstatfs" },            // 100
	{ "ioperm" },             // 101
	{ "socketcall" },         // 102
	{ "syslog" },             // 103
	{ "setitimer" },          // 104
	{ "getitimer" },          // 105
	{ "stat" },               // 106
	{ "lstat" },              // 107
	{ "fstat" },              // 108
	{ "olduname" },           // 109
	{ "iopl" },               // 110
	{ "vhangup" },            // 111
	{ "idle" },               // 112
	{ "vm86" },               // 113
	{ "wait4" },              // 114
	{ "swapoff" },            // 115
	{ "sysinfo" },            // 116
	{ "ipc" },                // 117
	{ "fsync" },              // 118
	{ "sigreturn" },          // 119
	{ "clone" },              // 120
	{ "setdomainname" },      // 121
	{ "uname" },              // 122
	{ "modify_ldt" },         // 123
	{ "adjtimex" },           // 124
	{ "mprotect" },           // 125
	{ "sigprocmask" },        // 126
	{ "create_module" },      // 127
	{ "init_module" },        // 128
	{ "delete_module" },      // 129
	{ "get_kernel_syms" },    // 130
	{ "quotactl" },           // 131
	{ "getpgid" },            // 132
	{ "fchdir" },             // 133
	{ "bdflush" },            // 134
	{ "sysfs" },              // 135
	{ "personality" },        // 136
	{ "afs_syscall" },        // 137
	{ "setfsuid" },           // 138
	{ "setfsgid" },           // 139
	{ "_llseek" },            // 140
	{ "getdents" },           // 141
	{ "_newselect" },         // 142
	{ "flock" },              // 143
	{ "msync" },              // 144
	{ "readv" },              // 145
	{ "writev" },             // 146
	{ "getsid" },             // 147
	{ "fdatasync" },          // 148
	{ "_sysctl" },            // 149
	{ "mlock" },              // 150
	{ "munlock" },            // 151
	{ "mlockall" },           // 152
	{ "munlockall" },         // 153
	{ "sched_setparam" },             // 154
	{ "sched_getparam" },             // 155
	{ "sched_setscheduler" },         // 156
	{ "sched_getscheduler" },         // 157
	{ "sched_yield" },                // 158
	{ "sched_get_priority_max" },     // 159
	{ "sched_get_priority_min" },     // 160
	{ "sched_rr_get_interval" },      // 161
	{ "nanosleep" },          // 162
	{ "mremap" },             // 163
	{ "setresuid" },          // 164
	{ "getresuid" },          // 165
	{ "query_module" },       // 166
	{ "poll" },               // 167
	{ "nfsservctl" },         // 168
	{ "setresgid" },          // 169
	{ "getresgid" },          // 170
	{ "prctl" },              // 171
	{ "rt_sigreturn" },       // 172
	{ "rt_sigaction" },       // 173
	{ "rt_sigprocmask" },     // 174
	{ "rt_sigpending" },      // 175
	{ "rt_sigtimedwait" },    // 176
	{ "rt_sigqueueinfo" },    // 177
	{ "rt_sigsuspend" },      // 178
	{ "pread64" },            // 179
	{ "pwrite64" },           // 180
	{ "chown" },              // 181
	{ "getcwd" },             // 182
	{ "capget" },             // 183
	{ "capset" },             // 184
	{ "sigaltstack" },        // 185
	{ "sendfile" },           // 186
	{ "getpmsg" },            // 187
	{ "putpmsg" },            // 188
	{ "vfork" },              // 189
	{ "ugetrlimit" },         // 190
	{ "readahead" },          // 191
	{ "mmap2" },              // 192
	{ "truncate64" },         // 193
	{ "ftruncate64" },        // 194
	{ "stat64" },             // 195
	{ "lstat64" },            // 196
	{ "fstat64" },            // 197
	{ "pciconfig_read" },     // 198
	{ "pciconfig_write" },    // 199
	{ "pciconfig_iobase" },   // 200
	{ "multiplexer" },        // 201
	{ "getdents64" },         // 202
	{ "pivot_root" },         // 203
	{ "fcntl64" },            // 204
	{ "madvise" },            // 205
	{ "mincore" },            // 206
	{ "gettid" },             // 207
	{ "tkill" },              // 208
	{ "setxattr" },           // 209
	{ "lsetxattr" },          // 210
	{ "fsetxattr" },          // 211
	{ "getxattr" },           // 212
	{ "lgetxattr" },          // 213
	{ "fgetxattr" },          // 214
	{ "listxattr" },          // 215
	{ "llistxattr" },         // 216
	{ "flistxattr" },         // 217
	{ "removexattr" },        // 218
	{ "lremovexattr" },       // 219
	{ "fremovexattr" },       // 220
	{ "futex" },              // 221
	{ "sched_setaffinity" },  // 222
	{ "sched_getaffinity" },  // 223
	{ "tuxcall" },            // 225
	{ "sendfile64" },         // 226
	{ "io_setup" },           // 227
	{ "io_destroy" },         // 228
	{ "io_getevents" },       // 229
	{ "io_submit" },          // 230
	{ "io_cancel" },          // 231
	{ "set_tid_address" },    // 232
	{ "fadvise64" },          // 233
	{ "exit_group" },         // 234
	{ "lookup_dcookie" },     // 235
	{ "epoll_create" },       // 236
	{ "epoll_ctl" },          // 237
	{ "epoll_wait" },         // 238
	{ "remap_file_pages" },   // 239
	{ "timer_create" },       // 240
	{ "timer_settime" },      // 241
	{ "timer_gettime" },      // 242
	{ "timer_getoverrun" },   // 243
	{ "timer_delete" },       // 244
	{ "clock_settime" },      // 245
	{ "clock_gettime" },      // 246
	{ "clock_getres" },       // 247
	{ "clock_nanosleep" },    // 248
	{ "swapcontext" },        // 249
	{ "tgkill" },             // 250
	{ "utimes" },             // 251
	{ "statfs64" },           // 252
	{ "fstatfs64" },          // 253
	{ "fadvise64_64" },       // 254
	{ "rtas" },               // 255
	{ "sys_debug_setcontext" }, // 256
	{ "reserved" },           // 257
	{ "migrate_pages" },      // 258
	{ "mbind" },              // 259
	{ "get_mempolicy" },      // 260
	{ "set_mempolicy" },      // 261
	{ "mq_open" },            // 262
	{ "mq_unlink" },          // 263
	{ "mq_timedsend" },       // 264
	{ "mq_timedreceive" },    // 265
	{ "mq_notify" },          // 266
	{ "mq_getsetattr" },      // 267
	{ "kexec_load" },         // 268
	{ "add_key" },            // 269
	{ "request_key" },        // 270
	{ "keyctl" },             // 271
	{ "waitid" },             // 272
	{ "ioprio_set" },         // 273
	{ "ioprio_get" },         // 274
	{ "inotify_init" },       // 275
	{ "inotify_add_watch" },  // 276
	{ "inotify_rm_watch" },   // 277
	{ "spu_run" },            // 278
	{ "spu_create" },         // 279
	{ "pselect6" },           // 280
	{ "ppoll" },              // 281
	{ "unshare" },            // 282
	{ "splice" },             // 283
	{ "tee" },                // 284
	{ "vmsplice" },           // 285
	{ "openat" },             // 286
	{ "mkdirat" },            // 287
	{ "mknodat" },            // 288
	{ "fchownat" },           // 289
	{ "futimesat" },          // 290
	{ "newfstatat" },         // 291
	{ "unlinkat" },           // 292
	{ "renameat" },           // 293
	{ "linkat" },             // 294
	{ "symlinkat" },          // 295
	{ "readlinkat" },         // 296
	{ "fchmodat" },           // 297
	{ "faccessat" },          // 298
	{ "get_robust_list" },    // 299
	{ "set_robust_list" },    // 300
	{ "move_pages" },         // 301
	{ "getcpu" },             // 302
	{ "epoll_pwait" },        // 303
	{ "utimensat" },          // 304
	{ "signalfd" },           // 305
	{ "timerfd_create" },     // 306
	{ "eventfd" },            // 307
	{ "sync_file_range2" },   // 308
	{ "fallocate" },          // 309
	{ "subpage_prot" },       // 310
	{ "timerfd_settime" },    // 311
	{ "timerfd_gettime" },    // 312
	{ "signalfd4" },          // 313
	{ "eventfd2" },           // 314
	{ "epoll_create1" },      // 315
	{ "dup3" },               // 316
	{ "pipe2" },              // 317
	{ "inotify_init1" },      // 318
	{ "perf_event_open" },    // 319
	{ "preadv" },             // 320
	{ "pwritev" },            // 321
	{ "rt_tgsigqueueinfo" },  // 322
	{ "fanotify_init" },      // 323
	{ "fanotify_mark" },      // 324
	{ "prlimit64" },          // 325
	{ "socket" },             // 326
	{ "bind" },               // 327
	{ "connect" },            // 328
	{ "listen" },             // 329
	{ "accept" },             // 330
	{ "getsockname" },        // 331
	{ "getpeername" },        // 332
	{ "socketpair" },         // 333
	{ "send" },               // 334
	{ "sendto" },             // 335
	{ "recv" },               // 336
	{ "recvfrom" },           // 337
	{ "shutdown" },           // 338
	{ "setsockopt" },         // 339
	{ "getsockopt" },         // 340
	{ "sendmsg" },            // 341
	{ "recvmsg" },            // 342
	{ "recvmmsg" },           // 343
	{ "accept4" },            // 344
	{ "name_to_handle_at" },  // 345
	{ "open_by_handle_at" },  // 346
	{ "clock_adjtime" },      // 347
	{ "syncfs" },             // 348
	{ "sendmmsg" },           // 349
	{ "setns" },              // 350
	{ "process_vm_readv" },   // 351
	{ "process_vm_writev" },  // 352
	{ "finit_module" },       // 353
	{ "kcmp" },               // 354
	{ "sched_setattr" },      // 355
	{ "sched_getattr" },      // 356
	{ "renameat2" },          // 357
	{ "seccomp" },            // 358
	{ "getrandom" },          // 359
	{ "memfd_create" },       // 360
	{ "bpf" },                // 361
	{ "execveat" },           // 362
	{ "switch_endian" },      // 363
	{ "userfaultfd" },        // 364
	{ "membarrier" },         // 365
	{ "mlock2" },             // 378
	{ "copy_file_range" },    // 379
	{ "preadv2" },            // 380
	{ "pwritev2" },           // 381
	{ "kexec_file_load" },    // 382
	{ "statx" },              // 383
	{ "pkey_alloc" },         // 384
	{ "pkey_free" },          // 385
	{ "pkey_mprotect" },      // 386
	{ "rseq" },               // 387
	{ "io_pgetevents" },      // 388
	{ "UNKNOWN" },		  // 389
};
#define NR_SYSCALLS (sizeof(syscalls) / sizeof(struct call))

struct stats {
	uint64_t total;
	uint64_t system;
	uint64_t opal;
	uint64_t user;
	uint64_t userlib;
	uint64_t userbin;
	uint64_t scnum;
	uint64_t idle;
	uint64_t mftb_last;
	uint64_t ctxswitch;
	uint64_t ctxswitch_ea;
	uint64_t ctxswitch_ea_multiple;
	struct exception *exceptions;
	struct call *syscalls;
};
struct stats s = {
	.syscalls = syscalls,
	.exceptions = exceptions,
};

static bool is_exception_entry(unsigned long ea)
{
	unsigned long exception;
	int i;

	if (((ea & 0xfffffffffffff000) != 0xc000000000004000) &&
	    ((ea & 0xfffffffffffff000) != 0x0000000000000000))
		return false;

	exception = (ea & 0xfff);
	for (i = 0; i < NR_EXCEPTIONS; i++) {
		if (exception == s.exceptions[i].addr) {
			s.exceptions[i].count++;
			return true;
		}
	}

	return false;
}

void ppcstats_log_inst(unsigned long ea, uint32_t insn)
{
	uint32_t i;
	bool system = false;

	s.total++;
	if (ea >= 0xc000000000000000) {
		system = true;
		s.system++;
	} else if ((ea & 0xFFFFFFFFFF000000) == 0x0000000030000000)
		s.opal++;
	else {
		s.user++;
		if (ea >= 0x700000000000)
			s.userlib++;
		else
			s.userbin++;
	}

	is_exception_entry(ea);

	/* Find syscalls */
	/* li r0, ??*/
	if ((insn & 0xffff0000) == 0x38000000) {
		s.scnum = insn & 0x0000ffff;
	}
	if (insn == 0x44000002) { /* sc */
		/* check for bogus value */
		if (s.scnum > NR_SYSCALLS)
			s.scnum = NR_SYSCALLS - 1;
		s.syscalls[s.scnum].count++;
		s.scnum = NR_SYSCALLS - 1; /* make sure we don't count this again */
	}

	/* Context switch */
	/* mfspr r??, SPRN_EBBRR in kernel == context switch */
	if (system && ((insn & 0xfe1fffff) == 0x7c0042a6)) {
		s.ctxswitch++;
		if (!s.ctxswitch_ea)
			s.ctxswitch_ea = ea;
		/* double check we aren't doing tm, signals or kvm */
		if (ea != s.ctxswitch_ea)
			s.ctxswitch_ea_multiple++;
	}

	/* look for mftb r??  within 10 cycles */
	if (system && ((insn & 0xfc1fffff) == 0x7c0c42a6)) {
		i = s.total - s.mftb_last;
		if (i < 10)
			/* We are in the snoop loop */
			s.idle += i;
		s.mftb_last = s.total;
	}

}

static int exceptions_compare(const void *a, const void *b)
{
	return ((struct exception *)b)->count - ((struct exception *)a)->count;
}

static int call_compare(const void *a, const void *b)
{
	return ((struct call *)b)->count - ((struct call *)a)->count;
}

void ppcstats_print(void)
{
	int i;
	float f;

	fprintf(stdout,"\n");
	fprintf(stdout,"Instructions:\n");
	fprintf(stdout,"  %-16s%li\n", "Total", s.total);
	fprintf(stdout,"    %-14s%8li\t%6.2f%% of Total\n", "System",
		s.system, 100.0*s.system/s.total);
	fprintf(stdout,"      %-12s%8li\t%6.2f%% of System\n", "Idle",
		s.idle, 100.0*s.idle/s.system);

	fprintf(stdout,"    %-14s%8li\t%6.2f%% of Total\n", "OPAL",
		s.opal, 100.0*s.opal/s.total);
	fprintf(stdout,"    %-14s%8li\t%6.2f%% of Total\n", "User",
		s.user, 100.0*s.user/s.total);

	fprintf(stdout,"      %-12s%8li\t%6.2f%% of User\n", "Bin",
		s.userbin, 100.0*s.userbin/s.user);
	fprintf(stdout,"      %-12s%8li\t%6.2f%% of User\n", "Lib",
		s.userlib, 100.0*s.userlib/s.user);


	fprintf(stdout,"\nContext Switches %16li\n", s.ctxswitch);
	f = 100.0 * s.ctxswitch_ea_multiple/s.ctxswitch;
	if (f > 10.0)
		fprintf(stdout,"WARNING: Context Switches fuzzy by %0.2f%%)\n", f);

	fprintf(stdout,"\nExceptions:\n");
	qsort(s.exceptions, NR_EXCEPTIONS, sizeof(struct exception), exceptions_compare);
	for (i = 0; i < NR_EXCEPTIONS; i++) {
		if (s.exceptions[i].count) {
			fprintf(stdout,"\t%16s\t%li\n",
			       s.exceptions[i].name,
			       s.exceptions[i].count);
		}
	}

	fprintf(stdout,"\nSyscalls:\n");
	qsort(s.syscalls, NR_SYSCALLS, sizeof(struct call), call_compare);
	for (i = 0; i < NR_SYSCALLS; i++) {
		if (!syscalls[i].count)
			break;
		fprintf(stdout,"\t%16s\t%li\n",
		       syscalls[i].name, syscalls[i].count);
	}
}
