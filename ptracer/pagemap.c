#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int pm_fd = -1;	/* /proc/pid/pagemap */
static int kpf_fd = -1;	/* /proc/kpageflags */

/*
 * We can't snoop tlb invalidates, so re-check pagemaps periodically.
 * 0 turns off the TLB entirely.
 *
 * Larger values will be faster but less accurate with respect to
 * changing memory maps and transparent hugepages etc. Make the i-side
 * cache a bunch of accesses becase they are more frequent and less
 * likely to change.
 *
 * This is about 5% overhead.
 */
#define REFRESH_INTERVAL_ISIDE 10000
#define REFRESH_INTERVAL_DSIDE 100

struct map {
	unsigned long ea;
	unsigned long pa;
	unsigned int access_seq;
};

static unsigned int access_seq;

#define BASE_MAP_SIZE (4096)
static unsigned long base_pshift;
static struct map base_map[BASE_MAP_SIZE];

#define HUGE_MAP_SIZE (4096)
static unsigned long huge_pshift;
static struct map huge_map[HUGE_MAP_SIZE];

bool init_pagemaps(pid_t pid, unsigned long basesz, unsigned long hugesz)
{
	char path[PATH_MAX];

	snprintf(path, PATH_MAX-1, "/proc/%d/pagemap", pid);

	pm_fd = open(path, O_RDONLY);
	if (pm_fd == -1) {
		perror("open pagemap");
		exit(1);
	}

	kpf_fd = open("/proc/kpageflags", O_RDONLY);
	if (kpf_fd == -1) {
		perror("open kpageflags");
		exit(1);
	}

	base_pshift = ffs(~(basesz-1)) - 1;
	huge_pshift = ffs(~(hugesz-1)) - 1;

	if (sysconf(_SC_PAGE_SIZE) != (1UL << base_pshift)) {
		fprintf(stderr, "page size does not match specified base\n");
		exit(1);
	}

	return true;
}

bool ea_to_pa(unsigned long ea, unsigned long *pa, unsigned long *pshift, bool iside)
{
	unsigned long bea_page = ea >> base_pshift;
	unsigned long hea_page = ea >> huge_pshift;
	unsigned long idx;
	unsigned long pagemap;
	unsigned long kpageflags;
	unsigned long max_interval;

	if (iside)
		max_interval = REFRESH_INTERVAL_ISIDE;
	else
		max_interval = REFRESH_INTERVAL_DSIDE;
	if (!max_interval)
		goto no_cache;
	access_seq++;

	idx = bea_page % BASE_MAP_SIZE;
	if (base_map[idx].ea == bea_page) {
		if (access_seq - base_map[idx].access_seq < max_interval) {
			*pshift = base_pshift;
			*pa = base_map[idx].pa;
			return true;
		}
	}

	idx = hea_page % BASE_MAP_SIZE;
	if (huge_map[idx].ea == hea_page) {
		if (access_seq - huge_map[idx].access_seq < max_interval) {
			*pshift = huge_pshift;
			*pa = huge_map[idx].pa;
			return true;
		}
	}

no_cache:
	/*
	 * XXX: if this occurs before the target instruction runs, it won't get
	 * faulted-in pages the first time around.
	 */
	idx = bea_page * 8;
	if (pread(pm_fd, &pagemap, 8, idx) == -1) {
		perror("pread pagemap");
		exit(1);
	}

	if (!(pagemap & (1UL<<63))) {
		return false; /* !present */
	}

	*pa = (pagemap & 0x3fffffffffffffULL) << base_pshift;
	idx = (*pa >> base_pshift) * 8;
	if (pread(kpf_fd, &kpageflags, 8, idx) == -1) {
		perror("pread pagemap");
		exit(1);
	}

	if (kpageflags & ((1UL<<17) | (1UL<<22))) {
		/* huge or transparent huge */
		idx = hea_page % HUGE_MAP_SIZE;
		*pshift = huge_pshift;
		if (max_interval) {
			huge_map[idx].ea = hea_page;
			huge_map[idx].pa = *pa;
			huge_map[idx].access_seq = access_seq;
		}
	} else {
		idx = bea_page % BASE_MAP_SIZE;
		*pshift = base_pshift;
		if (max_interval) {
			base_map[idx].ea = bea_page;
			base_map[idx].pa = *pa;
			base_map[idx].access_seq = access_seq;
		}
	}

	return true;
}

