#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

#include <ccan/tap/tap.h>

#include <qtlib/qtwriter.h>

#include <ppcstats.h>
#include "../htm.h"
#include "../tlb.h"
#include "bb.h"

#define MAX_TEST_CASES 30
#define MAX_EXPECTATIONS 30

#define offsetof(t, f)   __builtin_offsetof(t, f)
#define sizeof_field(t, f) (sizeof(((t*)0)->f))
#define array_count_pair(type, ...) { __VA_ARGS__ }, sizeof((const type[]){__VA_ARGS__})/sizeof(type)


#define TEST_CASES(...) array_count_pair(struct test_case*, __VA_ARGS__)
#define EXPECTATIONS(...) array_count_pair(struct test_expectation, __VA_ARGS__)

#define EXPECT(field) {						\
	.offset = offsetof(struct qtrace_record, field),	\
	.length = sizeof_field(struct qtrace_record, field),	\
	.name = #field						\
}

struct test_expectation {
	size_t offset;
	size_t length;
	char *name;
};

struct test_case {
	char *name;
	char *description;
	uint64_t record_number;
	struct qtrace_record expected;
	struct test_expectation expectations[MAX_EXPECTATIONS];
	int nexpectations;
};

struct test_file {
	char *filename;
	char *sha1sum;
	struct test_case const *test_cases[MAX_TEST_CASES];
	int ncases;
};

const struct test_case test_full_walk = {
	.name = "Test the first record containing a full walk.",
	.record_number = 1,
	.expected = {
		.radix_insn = {
			.nr_ptes = 3,
			.nr_pte_walks = 5,
			.guest_real_addrs = {
				[0] = 0x0000005b2e6307f8,
				[1] = 0x0000005af678cfd8,
				[2] = 0x0000005b5c5078b8,
				[3] = 0x0000005af199b3b0,
				[4] = 0x0000005973abbd60,
			},
			.host_ptes = {
				[0] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050b60,
					[2] = 0x0004301860f40b98,
				},
				[1] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050b58,
					[2] = 0x0004301860b00d98,
				},
				[2] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050b68,
					[2] = 0x0004301861380710,
				},
				[3] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b58,
					[2] = 0x4301860b00c60,
				},
				[4] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050b28,
					[2] = 0x000430185f180ce8,
				}
			},
			.host_real_addrs = {
				[0] = 0x0000105f6e6307f8,
				[1] = 0x0000105f3678cfd8,
				[2] = 0x0000105f9c5078b8,
				[3] = 0x0000105f3199b3b0,
			},
		},
		.insn_page_shift = 21,
		.insn_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x0000005b2e63fff0,
				[1] = 0x000000a0f2f48688,
				[2] = 0x000000cd71bbd970,
				[3] = 0x0000005bc9556d08,
				[4] = 0x0000005d76da9b48,
			},
			.host_ptes = {
				[0] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b60,
					[2] = 0x4301860f40b98,
				},
				[1] = {
					[0] = 0x0004301800000008,
					[1] = 0x0004301888440418,
					[2] = 0x00043018ab540cb8,
				},
				[2] = {
					[0] = 0x0004301800000008,
					[1] = 0x00043018884409a8,
					[2] = 0x00043018da9c0c68,
				},
				[3] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050b78,
					[2] = 0x0004301861c00250,
				},
				[4] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050ba8,
					[2] = 0x0004301863580db0,
				}
			},
			.host_real_addrs = {
				[0] = 0x0000105f6e63fff0,
				[1] = 0x00002070d2f48688,
				[2] = 0x0000304d71bbd970,
				[3] = 0x00002003e9556d08,
			},
		}
	},
	EXPECTATIONS(
		EXPECT(radix_insn.nr_ptes),
		EXPECT(radix_insn.nr_pte_walks),
		EXPECT(radix_insn.guest_real_addrs),
		EXPECT(radix_insn.host_real_addrs),
		EXPECT(radix_insn.host_ptes),
		EXPECT(insn_page_shift_valid),
		EXPECT(insn_page_shift),
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes),
	),
};

const struct test_case test_data_walk = {
	.name = "Test the second record contains a d-walk and shares i-walk.",
	.record_number = 2,
	.expected = {
		.insn = 0xf9250000,
		.insn_page_shift_valid = true,
		.guest_insn_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x0000005b2e63fff0,
				[1] = 0x000000a0f2f48b28,
				[2] = 0x0000005aee556ac8,
				[3] = 0x000000cc47ad00e0,
				[4] = 0x000000c9112804f0,
			},
			.host_ptes = {
				[0] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b60,
					[2] = 0x4301860f40b98,
				},
				[1] = {
					[0] = 0x4301800000008,
					[1] = 0x4301888440418,
					[2] = 0x43018ab540cb8,
				},
				[2] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b58,
					[2] = 0x4301860b00b90,
				},
				[3] = {
					[0] = 0x0004301800000008,
					[1] = 0x0004301888440988,
					[2] = 0x00043018d98c01e8,
				},
				[4] = {
					[0] = 0x0004301800000008,
					[1] = 0x0004301888440920,
					[2] = 0x00043018d6180448,
				}
			},
			.host_real_addrs = {
				[0] = 0x0000105f6e63fff0,
				[1] = 0x00002070d2f48b28,
				[2] = 0x0000105f2e556ac8,
				[3] = 0x0000304c47ad00e0,
			},
		}
	},
	EXPECTATIONS(
		EXPECT(insn),
		EXPECT(insn_page_shift_valid),
		EXPECT(guest_insn_page_shift_valid),
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes),
	),
};

const struct test_case test_branch_walk = {
	.name = "Test the i-side walk for a branch.",
	.record_number = 3,
	.expected = {
		.insn = 0x4e800020,
		.insn_page_shift_valid = true,
		.guest_insn_page_shift_valid = true,
		.radix_insn = {
			.nr_ptes = 3,
			.nr_pte_walks = 5,
			.guest_real_addrs = {
				[0] = 0x5b2e6307f8,
				[1] = 0x5af678cfd8,
				[2] = 0x5b5c5078b8,
				[3] = 0x5af199b3b0,
				[4] = 0x5973abbd68,
			},
			.host_ptes = {
				[0] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b60,
					[2] = 0x4301860f40b98,
				},
				[1] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b58,
					[2] = 0x4301860b00d98,
				},
				[2] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b68,
					[2] = 0x4301861380710,
				},
				[3] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b58,
					[2] = 0x4301860b00c60,
				},
				[4] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b28,
					[2] = 0x430185f180ce8,
				}
			},
			.host_real_addrs = {
				[0] = 0x105f6e6307f8,
				[1] = 0x105f3678cfd8,
				[2] = 0x105f9c5078b8,
				[3] = 0x105f3199b3b0,
			},
		}
	},
	EXPECTATIONS(
		EXPECT(insn),
		EXPECT(insn_page_shift_valid),
		EXPECT(guest_insn_page_shift_valid),
		EXPECT(radix_insn.guest_real_addrs),
		EXPECT(radix_insn.host_real_addrs),
		EXPECT(radix_insn.host_ptes),
	),
};

const struct test_case test_data_walk_cache = {
	.name = "Test a d-side walk influenced by the Page Walk Cache.",
	.record_number = 4,
	.expected = {
		.insn = 0xe8410018,
		.insn_page_shift_valid = true,
		.guest_insn_page_shift_valid = true,
		.radix_insn = {
			.nr_ptes = 3,
			.nr_pte_walks = 5,
			.guest_real_addrs = {
				[0] = 0x0000005b2e6307f8,
				[1] = 0x0000005af678cff0,
				[2] = 0x0000005b5c503d50,
				[3] = 0x0000005af1997b78,
				[4] = 0x0000002975939300,
			},
			.host_ptes = {
				[0] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b60,
					[2] = 0x4301860f40b98,
				},
				[1] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b58,
					[2] = 0x4301860b00d98,
				},
				[2] = {
					[0] = 0x4301800000000,
					[1] = 0x4301800050b68,
					[2] = 0x0004301861380710,
				},
				[3] = {
					[0] = 0x4301800000000,
					[1] = 0x0004301800050b58,
					[2] = 0x4301860b00c60,
				},
				[4] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050528,
					[2] = 0x000430182c180d60,
				}
			},
			.host_real_addrs = {
				[0] = 0x0000105f6e6307f8,
				[1] = 0x0000105f3678cff0,
				[2] = 0x0000105f9c503d50,
				[3] = 0x0000105f31997b78,
			},
		},
		.radix_data = {
			.guest_real_addrs = {
				[3] = 0x0000009cbc8a5ff8,
				[4] = 0x0000001d83d48038,
			},
			.host_ptes = {
				[3] = {
					[0] = 0x0004301800000008,
					[1] = 0x0004301888440390,
					[2] = 0x00043018a6d00f20,
				},
				[4] = {
					[0] = 0x0004301800000000,
					[1] = 0x00043018000503b0,
					[2] = 0x000430181f9c00f0,
				}
			},
			.host_real_addrs = {
				[2] = 0x0000105f9c507710,
				[3] = 0x0000206c9c8a5ff8,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(insn),
		EXPECT(insn_page_shift_valid),
		EXPECT(guest_insn_page_shift_valid),
		EXPECT(guest_insn_page_shift_valid),
		EXPECT(radix_insn.guest_real_addrs),
		EXPECT(radix_insn.host_real_addrs),
		EXPECT(radix_insn.host_ptes),
		EXPECT(radix_data.guest_real_addrs[3]),
		EXPECT(radix_data.guest_real_addrs[4]),
		EXPECT(radix_data.host_real_addrs[2]),
		EXPECT(radix_data.host_real_addrs[3]),
		EXPECT(radix_data.host_ptes[3]),
		EXPECT(radix_data.host_ptes[4]),
		EXPECT(data_page_shift_valid),
	),
};

const struct test_case test_data_huge_page = {
	.name = "Test a d-side huge page.",
	.record_number = 38,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.data_page_shift = 21,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x0000005b2e63fff0,
				[1] = 0x000000a0f2f489e8,
				[2] = 0x0000005b720ee528,
				[3] = 0x000000d52a769fb8,
				[4] = 0x000000c98a33dc70,
			},
			.host_ptes = {
				[2] = {
					[2] = 0x0004301861380c80,
				},
				[3] = {
					[0] = 0x0004301800000008,
					[1] = 0x0004301888440aa0,
					[2] = 0x00043018e2d80a98,
				}
			},
			.host_real_addrs = {
				[0] = 0x0000105f6e63fff0,
				[1] = 0x00002070d2f489e8,
				[2] = 0x0000105fb20ee528,
				[3] = 0x000030552a769fb8,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes[2][2]),
		EXPECT(radix_data.host_ptes[3]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
		EXPECT(data_page_shift),
	),
};

const struct test_case test_data_erat_cache = {
	.name = "Test a d-side ERAT hit.",
	.record_number = 5,
	.expected = {
		.insn = 0xe8010030,
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(insn),
		EXPECT(data_page_shift_valid),
	),
};

const struct test_case test_correct_page_size = {
	.name = "Test correctly identify 64K pages.",
	.record_number = 104,
	.expected = {
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x0000005b2e63fff0,
				[1] = 0x000000a0f2f489e8,
				[2] = 0x0000005b720ee528,
				[3] = 0x000000d52a769fb8,
				[4] = 0x000000c98a33b2f8,
			},
			.host_real_addrs = {
				[0] = 0x0000105f6e63fff0,
				[1] = 0x00002070d2f489e8,
				[2] = 0x0000105fb20ee528,
				[3] = 0x000030552a769fb8,
			},
		},
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
	),
};

const struct test_case test_new_pid = {
	.name = "Test changing PIDs.",
	.record_number = 32795,
	.expected = {
		.insn = 0x7db243a6,
		.radix_insn = {
			.nr_ptes = 3,
			.nr_pte_walks = 4,
			.guest_real_addrs = {
				[0] = 0x00000000017e0000,
				[1] = 0x000000fffffe0000,
				[2] = 0x000000fffffd0000,
				[3] = 0x0000000000004900,
			},
			.host_ptes = {
				[0] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050000,
					[2] = 0x0004301800440058,
				},
				[1] = {
					[2] = 0x0004301910440ff8,
				},
				[2] = {
					[0] = 0x0004301800000008,
					[1] = 0x0004301888440ff8,
					[2] = 0x0004301910440ff8,
				},
				[3] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050000,
					[2] = 0x0004301800440000,
				},
			},
			.host_real_addrs = {
				[0] = 0x00000064017e0000,
				[1] = 0x0000307ffffe0000,
				[2] = 0x0000307ffffd0000,
			},
		},
		.insn_page_shift = 21,
		.insn_page_shift_valid = true,
		.guest_insn_page_shift = 21,
		.guest_insn_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(insn),
		EXPECT(radix_insn.nr_ptes),
		EXPECT(radix_insn.nr_pte_walks),
		EXPECT(radix_insn.guest_real_addrs),
		EXPECT(radix_insn.host_real_addrs),
		EXPECT(radix_insn.host_ptes[0]),
		EXPECT(radix_insn.host_ptes[1][2]),
		EXPECT(radix_insn.host_ptes[2]),
		EXPECT(radix_insn.host_ptes[3]),
		EXPECT(insn_page_shift_valid),
		EXPECT(insn_page_shift),
		EXPECT(guest_insn_page_shift_valid),
		EXPECT(guest_insn_page_shift),
	),
};

const struct test_case test_cached_pid = {
	.name = "Test ERAT with a new PID.",
	.record_number = 32823,
	.expected = {
		.insn = 0x718a4000,
	},
	EXPECTATIONS(
		EXPECT(insn),
	),
};

const struct test_case test_interupted_xlate = {
	.name = "Test merging an XLATE after being interrupted before complete.",
	.record_number = 36477,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[3] = 0x0000005b9cf5f630,
				[4] = 0x00000066b98d4688,
			},
			.host_ptes = {
				[3] = {
					[2] = 0x00043018617c0738,
				},
				[4] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050cd0,
					[2] = 0x000430186d2c0e60,
				}
			},
			.host_real_addrs = {
				[2] = 0x00002049d29b8818,
				[3] = 0x0000105fdcf5f630,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs[3]),
		EXPECT(radix_data.guest_real_addrs[4]),
		EXPECT(radix_data.host_real_addrs[2]),
		EXPECT(radix_data.host_real_addrs[3]),
		EXPECT(radix_data.host_ptes[3][2]),
		EXPECT(radix_data.host_ptes[4][0]),
		EXPECT(radix_data.host_ptes[4][1]),
		EXPECT(radix_data.host_ptes[4][2]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_case test_infer_from_host_level4 = {
	.name = "Test infering an XLATE continuing from only the host level 4.",
	.record_number = 176961,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x0000005b2e63fff0,
				[1] = 0x000000a0f2f487c8,
				[2] = 0x000000cc783e1570,
				[3] = 0x000000c3f57ffbf8,
				[4] = 0x000000c604cc28a0,
			},
			.host_ptes = {
				[0] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050b60,
					[2] = 0x0004301860f40b98,
				},
				[1] = {
					[0] = 0x0004301800000008,
					[1] = 0x0004301888440418,
					[2] = 0x00043018ab540cb8,
				},
				[2] = {
					[0] = 0x0004301800000008,
					[1] = 0x0004301888440988,
					[2] = 0x00043018d98c0e08,
				},
				[3] = {
					[0] = 0x0004301800000008,
					[1] = 0x0004301888440878,
					[2] = 0x00043018d0840d58,
				},
				[4] = {
					[0] = 0x0004301800000008,
					[1] = 0x00043018884408c0,
					[2] = 0x00043018d2e80130,
				}
			},
			.host_real_addrs = {
				[0] = 0x0000105f6e63fff0,
				[1] = 0x00002070d2f487c8,
				[2] = 0x0000304c783e1570,
				[3] = 0x00003043f57ffbf8,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_case test_hv_interrupt_with_pr_xlate = {
	.name = "Test HV interrupt with full PR XLATE.",
	.record_number = 1850697,
	.expected = {},
	EXPECTATIONS(),
};

const struct test_case hrifd_and_use_interrupted_xlate = {
	.name = "Test return from HV interrupt a use previous PR XLATE.",
	.record_number = 1851765,
	.expected = {},
	EXPECTATIONS(),
};

const struct test_case test_different_page_sizes = {
	.name = "Test different page sizes in the same PDE",
	.record_number = 3979845,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.guest_data_page_shift = 16,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x00000000017ea000,
				[1] = 0x0000000780542010,
				[2] = 0x00000007804c00a8,
				[3] = 0x00000007804dda20,
				[4] = 0x000004017f5e0000,
			},
			.host_ptes = {
				[1] = {
					[2] = 0x00043018083c0010,
				},
				[2] = {
					[2] = 0x00043018083c0010,
				},
				[3] = {
					[2] = 0x00043018083c0010,
				},
				[4] = {
					[0] = 0x0004301800000040,
					[1] = 0x0004301910880028,
					[2] = 0x0004301913300fd0,
					[3] = 0x0004301913fc0f00,
				},
			},
			.host_real_addrs = {
				[0] = 0x00000064017ea000,
				[1] = 0x00001000a0542010,
				[2] = 0x00001000a04c00a8,
				[3] = 0x00001000a04dda20,
			},
			.nr_ptes = 4,
		},
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes[1][2]),
		EXPECT(radix_data.host_ptes[2][2]),
		EXPECT(radix_data.host_ptes[3][2]),
		EXPECT(radix_data.host_ptes[4]),
		EXPECT(radix_data.nr_ptes),
		EXPECT(guest_data_page_shift),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_case test_create_final_record_for_interrupted_xlate = {
	.name = "Test creating a final record for an interrupted XLATE.",
	.record_number = 83622485,
	.expected = {},
	EXPECTATIONS(),
};

const struct test_case test_infer_multi_interrupted_xlate = {
	.name = "Test inferring an XLATE interrupted multiple times.",
	.record_number = 95528562,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x000000d3b79107f8,
				[1] = 0x0000005b0c950ff0,
				[2] = 0x000000ffe70923c0,
				[3] = 0x000000ffef770468,
				[4] = 0x0000001c6cf73f70,
			},
			.host_ptes = {
				[0] = {
					[2] = 0x00043018e1400de0,
				},
				[2] = {
					[2] = 0x00043019104409c0,
				},
				[3] = {
					[2] = 0x0004301910440bd8,
				},
				[4] = {
					[2] = 0x000430181e480b38,
				}
			},
			.host_real_addrs = {
				[0] = 0x00003053b79107f8,
				[1] = 0x0000105f4c950ff0,
				[2] = 0x0000307fe70923c0,
				[3] = 0x0000307fef770468,
			},
		},
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes[0][2]),
		EXPECT(radix_data.host_ptes[2][2]),
		EXPECT(radix_data.host_ptes[3][2]),
		EXPECT(radix_data.host_ptes[4][2]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_case test_looking_up_guest_ra = {
	.name = "Test inferring an XLATE using the guest's pid",
	.record_number = 95608421,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x000000d3b79107f8,
				[1] = 0x0000005b0c950ff0,
				[2] = 0x000000ffe70923b8,
			},
			.host_real_addrs = {
				[0] = 0x00003053b79107f8,
				[1] = 0x0000105f4c950ff0,
				[2] = 0x0000307fe70923b8,
			},
		},
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs[0]),
		EXPECT(radix_data.guest_real_addrs[1]),
		EXPECT(radix_data.guest_real_addrs[2]),
		EXPECT(radix_data.host_real_addrs[0]),
		EXPECT(radix_data.host_real_addrs[1]),
		EXPECT(radix_data.host_real_addrs[2]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_case test_dcbt_xlates_are_cached = {
	.name = "Test data cache instruction's XLATEs are cached.",
	.record_number = 95916656,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x0000005ba6de0000,
				[1] = 0x0000005ba5420020,
				[2] = 0x0000005b333a2d10,
				[3] = 0x0000005ba6a00250,
				[4] = 0x0000001c1dce02b8,
			},
			.host_ptes = {
				[0] = {
					[2] = 0x00043018617c09b0,
				},
				[1] = {
					[2] = 0x00043018617c0950,
				},
				[2] = {
					[2] = 0x0004301860f40cc8,
				},
				[3] = {
					[2] = 0x00043018617c09a8,
				},
				[4] = {
					[2] = 0x000430181e040770,
				}
			},
			.host_real_addrs = {
				[0] = 0x0000105fe6de0000,
				[1] = 0x0000105fe5420020,
				[2] = 0x0000105f733a2d10,
				[3] = 0x0000105fe6a00250,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes[0][2]),
		EXPECT(radix_data.host_ptes[1][2]),
		EXPECT(radix_data.host_ptes[2][2]),
		EXPECT(radix_data.host_ptes[3][2]),
		EXPECT(radix_data.host_ptes[4][2]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_case test_1gb_page_sizes = {
	.name = "Test 1GB pages.",
	.record_number = 122841283,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.guest_data_page_shift = 21,
		.data_page_shift = 30,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x00000000017ea000,
				[1] = 0x0000000780542010,
				[2] = 0x00000007804c0230,
				[3] = 0x0000040101c42238,
			},
			.host_ptes = {
				[0] = {
					[2] = 0x00043018617c09b0,
				},
				[1] = {
					[2] = 0x00043018617c0950,
				},
				[2] = {
					[2] = 0x0004301860f40cc8,
				},
				[3] = {
					[0] = 0x0004301800000040,
					[1] = 0x0004301910880020,
				},
			},
			.host_real_addrs = {
				[0] = 0x00000064017ea000,
				[1] = 0x00001000a0542010,
				[2] = 0x00001000a04c0230,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes[3][0]),
		EXPECT(radix_data.host_ptes[3][1]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
		EXPECT(guest_data_page_shift),
		EXPECT(data_page_shift),
	),
};

const struct test_case test_non_leaf_in_pde_with_1gb_pages = {
	.name = "Test smaller pages in a PDE that contains 1GB pages.",
	.record_number = 122841721,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.guest_data_page_shift = 16,
		.data_page_shift = 12,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x00000000017ea000,
				[1] = 0x0000000780542010,
				[2] = 0x00000007804c01d0,
				[3] = 0x0000005bb5c4bc78,
				[4] = 0x000004001a750400,
			},
			.host_ptes = {
				[0] = {
					[2] = 0x00043018617c09b0,
				},
				[1] = {
					[2] = 0x00043018617c0950,
				},
				[2] = {
					[2] = 0x0004301860f40cc8,
				},
				[3] = {
					[2] = 0x00043018617c0d70,
				},
				[4] = {
					[0] = 0x0004301800000040,
					[1] = 0x0004301910880000,
					[2] = 0x0004301915940698,
					[3] = 0x00043019194c0a80,
				}
			},
			.host_real_addrs = {
				[0] = 0x00000064017ea000,
				[1] = 0x00001000a0542010,
				[2] = 0x00001000a04c01d0,
				[3] = 0x0000105ff5c4bc78,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes[3][2]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
		EXPECT(guest_data_page_shift),
		EXPECT(data_page_shift),
	),
};

const struct test_case test_retain_1gb_pages = {
	.name = "Test retaining 1GB page information",
	.record_number = 122843691,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.guest_data_page_shift = 21,
		.data_page_shift = 30,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x00000000017ea000,
				[1] = 0x0000000780542010,
				[2] = 0x00000007804c0230,
				[3] = 0x0000040101c068e0,
			},
			.host_ptes = {
				[3] = {
					[0] = 0x0004301800000040,
					[1] = 0x0004301910880020,
				},
			},
			.host_real_addrs = {
				[0] = 0x00000064017ea000,
				[1] = 0x00001000a0542010,
				[2] = 0x00001000a04c0230,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes[3][0]),
		EXPECT(radix_data.host_ptes[3][1]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
		EXPECT(guest_data_page_shift),
		EXPECT(data_page_shift),
	),
};

const struct test_case test_a_different_pid = {
	.name = "Test XLATEs with a different PID",
	.record_number = 148707743,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x0000005bb42c0000,
				[1] = 0x0000005b978b8028,
				[2] = 0x0000005bb42f4058,
				[3] = 0x0000005bb4001448,
				[4] = 0x0000005d42c5c350,
			},
			.host_ptes = {
				[0] = {
					[2] = 0x00043018617c0d08,
				},
				[1] = {
					[2] = 0x00043018617c05e0,
				},
				[2] = {
					[2] = 0x00043018617c0d08,
				},
				[3] = {
					[2] = 0x00043018617c0d00,
				},
				[4] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050ba8,
					[2] = 0x00043018635800b0,
				},
			},
			.host_real_addrs = {
				[0] = 0x0000105ff42c0000,
				[1] = 0x0000105fd78b8028,
				[2] = 0x0000105ff42f4058,
				[3] = 0x0000105ff4001448,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes[0][2]),
		EXPECT(radix_data.host_ptes[1][2]),
		EXPECT(radix_data.host_ptes[2][2]),
		EXPECT(radix_data.host_ptes[3][2]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_case test_page_size_dependant_xlate = {
	.name = "Test an XLATE that depends on the page size",
	.record_number = 148831884,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x0000005bb42c0000,
				[1] = 0x0000005b978b8020,
				[2] = 0x0000005bb42f2288,
				[3] = 0x0000005bb4000360,
				[4] = 0x0000005ba9dee190,
			},
			.host_ptes = {
				[4] = {
					[2] = 0x00043018617c0a70,
				},
			},
			.host_real_addrs = {
				[0] = 0x0000105ff42c0000,
				[1] = 0x0000105fd78b8020,
				[2] = 0x0000105ff42f2288,
				[3] = 0x0000105ff4000360,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes[4][2]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_case test_another_page_size_dependant_xlate = {
	.name = "Test another XLATE that depends on the page size",
	.record_number = 150835056,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[0] = 0x00000000017e0000,
				[1] = 0x000000fffffe0b70,
				[2] = 0x000000fffe8f0cf8,
				[3] = 0x0000005bb3f5f648,
			},
			.host_ptes = {
				[3] = {
					[0] = 0x0004301800000000,
					[1] = 0x0004301800050b70,
					[2] = 0x00043018617c0cf8,
				},
			},
			.host_real_addrs = {
				[0] = 0x00000064017e0000,
				[1] = 0x0000307ffffe0b70,
				[2] = 0x0000307ffe8f0cf8,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs),
		EXPECT(radix_data.host_real_addrs),
		EXPECT(radix_data.host_ptes[3]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_case test_record_with_two_deas = {
	.name = "Test a record with two dea records.",
	.record_number = 333726235,
	.expected = {},
	EXPECTATIONS(),
};

const struct test_file test_file_1 = {
	.filename = "htm/tests/dumps/radixtest1.htm",
	.sha1sum = "37892aa891b5b0e4119dbbb18f42d554958e684b",
	TEST_CASES(
		&test_full_walk,
		&test_data_walk,
		&test_branch_walk,
		&test_data_walk_cache,
		&test_data_erat_cache,
		&test_data_huge_page,
		&test_correct_page_size,
		&test_new_pid,
		&test_cached_pid,
		&test_interupted_xlate,
		&test_infer_from_host_level4,
		&test_hv_interrupt_with_pr_xlate,
		&hrifd_and_use_interrupted_xlate,
		&test_create_final_record_for_interrupted_xlate,
		&test_different_page_sizes,
		&test_infer_multi_interrupted_xlate,
		&test_looking_up_guest_ra,
		&test_dcbt_xlates_are_cached,
		&test_1gb_page_sizes,
		&test_non_leaf_in_pde_with_1gb_pages,
		&test_retain_1gb_pages,
		&test_a_different_pid,
		&test_page_size_dependant_xlate,
		&test_another_page_size_dependant_xlate,
		&test_record_with_two_deas,
	),
};

const struct test_case test_beginning_in_interrupt = {
	.name = "Test beginning in a interrupt context.",
	.description = "The trace begins in an interrupt, this record is the rfid.",
	.record_number = 37942,
	.expected = {},
	EXPECTATIONS(),
};

const struct test_case test_rfid_with_exception_record = {
	.name = "Test XLATE info with an exception record.",
	.description = "This record follows an RFID and uses previously interrupted XLATE.\n\
	                The XLATE recorded ends with a WALK record with the Exception bit.",
	.record_number = 75483628,
	.expected = {},
	EXPECTATIONS(),
};

const struct test_file test_file_3 = {
	.filename = "htm/tests/dumps/radixtest3.htm",
	.sha1sum = "efe5cdcef15f9c4db820db7b34ef4a3e16e13182",
	TEST_CASES(
		&test_beginning_in_interrupt,
		&test_rfid_with_exception_record,
	),
};

const struct test_case test_guest_real_mode = {
	.name = "Test guest real mode",
	.record_number = 83667553,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = false,
		.data_page_shift = 21,
		.radix_data = {
			.type = GUEST_REAL,
			.nr_ptes = 3,
			.nr_pte_walks = 1,
			.host_ptes = {
				[0] = {
					[0] = 0x00000000017e0000,
					[1] = 0x000001fffffe0000,
					[2] = 0x0000c01403140060,
				},
			},
		},
	},
	EXPECTATIONS(
		EXPECT(radix_data.host_ptes),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_file test_file_2 = {
	.filename = "htm/tests/dumps/radixtest2.htm",
	.sha1sum = "8bc0ed36592e77b4bfb8a31255f885700b21aaa9",
	TEST_CASES(
		&test_guest_real_mode,
	),
};

const struct test_case test_interupt_end_xlate_with_final_ra = {
	.name = "Test an interrupted XLATE that includes a final RA record.",
	.record_number = 60203459,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[3] = 0x0000010c194c7610,
				[4] = 0x0000010be767a270,
			},
			.host_ptes = {
				[3] = {
					[2] = 0x0000c015205c0650,
				},
				[4] = {
					[2] = 0x0000c015201809d8,
				},
			},
			.host_real_addrs = {
				[2] = 0x000080783dbe0468,
				[3] = 0x00008076694c7610,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs[3]),
		EXPECT(radix_data.guest_real_addrs[4]),
		EXPECT(radix_data.host_real_addrs[2]),
		EXPECT(radix_data.host_real_addrs[3]),
		EXPECT(radix_data.host_ptes[3][2]),
		EXPECT(radix_data.host_ptes[4][2]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_case test_interupt_end_xlate_without_final_ra = {
	.name = "Test an interrupted XLATE that does not include a final RA record.",
	.description = "When an interrupted XLATE does not include a final RA record\n" \
	               "one must created.",
	.record_number = 118015362,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.radix_data = {
			.guest_real_addrs = {
				[3] = 0x000001159d4b40c0,
			},
			.host_ptes = {
				[3] = {
					[2] = 0x0000c0152a740750,
				},
			},
			.host_real_addrs = {
				[2] = 0x00014011eba50750,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs[3]),
		EXPECT(radix_data.host_real_addrs[2]),
		EXPECT(radix_data.host_ptes[3][2]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
	),
};

const struct test_case test_resumed_xlate_with_no_guest_ra = {
	.name = "Test a resumed XLATE that skips the guest RA.",
	.description = "The page table walk was interruped but when it resumes\n" \
	               "it resumes with the host RA, so the guest RA must be inferred.",
	.record_number = 136384976,
	.expected = {
		.data_page_shift_valid = true,
		.guest_data_page_shift_valid = true,
		.guest_data_page_shift = 16,
		.radix_data = {
			.guest_real_addrs = {
				[3] = 0x0000017fd1bb1578,
				[4] = 0x0000017278674f68,
			},
			.host_ptes = {
				[4] = {
					[2] = 0x0000c0158d000e18,
				},
			},
			.host_real_addrs = {
				[3] = 0x0000c07fd1bb1578,
			},
		},
		.data_page_shift_valid = true,
	},
	EXPECTATIONS(
		EXPECT(radix_data.guest_real_addrs[3]),
		EXPECT(radix_data.guest_real_addrs[4]),
		EXPECT(radix_data.host_real_addrs[3]),
		EXPECT(radix_data.host_ptes[4][2]),
		EXPECT(data_page_shift_valid),
		EXPECT(guest_data_page_shift_valid),
		EXPECT(guest_data_page_shift),
	),
};

const struct test_file test_file_4 = {
	.filename = "htm/tests/dumps/radixtest4.htm",
	.sha1sum = "295f939aaf06842d8c7cdfbe294476d2cefc1682",
	TEST_CASES(
		&test_interupt_end_xlate_with_final_ra,
		&test_interupt_end_xlate_without_final_ra,
		&test_resumed_xlate_with_no_guest_ra,
	),
};

uint64_t record_count;

static void test_record(const struct test_case *test_case,
			struct qtrace_record *record)
{
	const struct qtrace_record *expected;
	const struct test_expectation *e;
	int ret;

	expected = &test_case->expected;
	for (e = test_case->expectations; e < test_case->expectations + test_case->nexpectations; e++) {
		ret = memcmp((char *)expected + e->offset,
			(char *)record + e->offset, e->length);
		if (ret != 0) {
			fail(test_case->name);
			diag("%s differs", e->name);
			return;
		}
	}
	pass(test_case->name);
}

static void test_records(struct htm_record *rec, void *private_data)
{
	struct qtrace_record record = rec->insn;
	const struct test_case **test_cases;
	struct test_file *test;

	test = (struct test_file *)private_data;
	test_cases = test->test_cases;
	for (int i = 0; i < test->ncases; i++) {
		if (record_count == test_cases[i]->record_number) {
			test_record(test_cases[i], &record);
			break;
		}
	}
	record_count++;
}

static void run_test_file(const struct test_file *test)
{
	int fd;

	record_count = 0;
	fd = open(test->filename, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Failed to open %s - %s\n",
			test->filename, strerror(errno));
		exit(1);
	}

	htm_decode(fd, test_records, (void *)test, NULL);
}

int main(int argc, char * const argv[])
{

	run_test_file(&test_file_1);
	run_test_file(&test_file_2);
	run_test_file(&test_file_3);
	run_test_file(&test_file_4);

	return 0;
}
