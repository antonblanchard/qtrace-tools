htmdecoder
==========

Overview
--------

`htmdecoder` converts Core HTM binary traces to Qtrace format traces.

A Core HTM trace is the direct binary output of the Core Hardware Trace Macro
logic unit. This capability is present on POWER8 and POWER10. The trace
combines debug bus output from various units and is as a result is quite low
level. The POWER10 HTM format is described elsewhere.

The main use case for tracing is performance analysis and the HTM trace is
too "raw" to be directly used for this. On the other hand, the Qtrace format is
readily usable for performance analysis.

Usage
-----

	Usage: ./htm/htmdecoder [-Ddsib]... [-o <outfile.qt>] <htmdump>

	-D 			Debug info
	-d 			Dump with some details
	-s 			Dump stats
	-i 			Dump instruction mix
	-b 			Basic block anaylsis

Testing
-------

Integration tests between `qtdis` and `htmdecoder` are run by `tests/run_tests`.
Tests are added by adding a:

  * Description to `tests/desc`
  * Minimal HTM dump to `tests/dumps`
  * Expected disassembly to `tests/disasms`


Behavioral tests for are in `htm/tests/*test*.c`. These rely on a specific HTM
dumps and assert the dump is being decoded as expected.

Implementation
--------------

`htmdecoder` uses `qtlib` for creating Qtrace files. The following is a
description of the other main files.

### htm.c

`htm.c` is the main file for the `htm` "library". The entry point is `htm_decode
()`. `htm_decode()` is given a HTM file it should read from and callback that
is should call after decoding each individual HTM record.

It then proceeds to call `htm_decode_one()` until the end of the HTM trace file
is reached. `htm_decode_one()` decodes the binary data of a single record into
a `struct htm_record`. This is a union containing the different record types
that may be in a HTM trace.

	struct htm_record {
		enum htm_record_type type;
		union {
			struct htm_record_record record;
			struct htm_record_complete complete;
			struct htm_record_pause pause;
			struct htm_record_mark mark;
			struct htm_record_sync sync;
			struct htm_record_time time;
			struct qtrace_record insn;
		};
	};

For `STAMP` type records there is not much to do but for `INSTRUCTION` type
records this is more involved as a `struct qtrace_record` must be created.
`struct qtrace_record` is defined in `qtlib/qtrace_record.h`.

The `INSTRUCTION` type record handling is done by `htm_decode_insn()` on POWER8
and `htm_decode_insn_p10()` on POWER10. This first parses the HTM binary data
into a `struct htm_insn insn` or `struct htm_insn insn_p10`. `struct htm_insn
insn` is the direct C struct representation of the HTM record format.

At the end of `htm_decode_insn()` the `struct htm_insn` is converted to
a `struct qtrace_record` to be used by the callback passed into
`htm_decode()`.

While the `struct htm_insn` and `struct qtrace_record` formats themselves
contain more (or less) equivalent information, the complication in creating
them arises as the HTM trace `struct htm_insn` comes from the hardware and so
as caches etc operate not all the data is always present as it depends on prior
records in the trace.

The `struct qtrace_record` must contain this data anyway, so enough state needs
to be maintained so that the required values can be determined.

### xlate.c

`xlate.c` is used by `htm.c` on POWER10. It handles decoding the XLATE records
that contain the Radix Walk information. This needs to handle the effects of
the hardware caches on the WALK records present in the trace, as well as the
fact that partial Radix Walks can be present in the HTM trace. See Appendix A.

### erat.c

`erat.c` is used by `xlate.c` on POWER10. It simulates the operation of the
hardware ERAT cache. This is done in an indirect way as the state of the
hardware ERAT is not included in the HTM trace. The HTM trace includes
effective and real addresses for all memory accesses. erat uses these to return
a full radix walk for qtrace output.

### pwc.c

`pwc.c` is used by `xlate.c` on POWER10. It simulates the operation of the
hardware Radix MMU to track the complete radix walk for addresses. When memory
accesses are performed over the course of a HTM trace the hardware combined
PWC/TLB caches are primed and fewer XLATE records are in the trace. pwc "fills
in the blanks" so every memory access can include the entire radix walk for
qtrace output.

### tlb.c

`tlb.c` is used by `htm.c` on POWER8. It simulates the POWER8 Hash Page Table
MMU cache.

### htmdecoder.c

`htmdecoder.c` drives the overall operation of `htmdecoder`. This includes:

* Argument parsing
* Opening the input file
* Creating the output file
* Initializing the `htm` library
* Initializing the `qtwriter` library

The main work is in the call to `htm_decode()` with `print_record()` passed in
as the callback. `print_record()` calls `qtwriter_write_record()` to write the
record to the end of the Qtrace record being created.

When the end of the HTM file is reached `qtwriter_close()` closes the Qtrace
file.

Appendix A: XLATE Records
-------------------------

POWER10 HTM traces are complicated by the fact that XLATE records can be
interrupted before completion but still present in the trace.

### Case 1: Non-Interrupted Record

This is the easiest case to handle and requires no special treatment.

### Case 2: Incomplete XLATE Interrupted Record

Regardless of if the Exception bit is set an interrupted XLATE can be
determined:
  - D-side: an IEARA record arrives after
  - I-side: RA in the IEARA does not match the final real address of the XLATE.

The interrupted XLATE records can be saved. As the interrupted page walk is
incomplete, when it the instruction resumes more XLATE records will be sent.
The vast majority of the time, the resumed XLATE records have overlap with the
interrupted XLATE record.

To handle this case, before using an XLATE record check in the saved interrupted
XLATEs and if there is an XLATEs there that matches, merge them together and
use that.

### Case 3: Complete XLATE Interrupted Record

An interrupted XLATE record may be the end of a page walk. This means upon
resumption no more XLATE records will be sent. However, the final real address
of the XLATE record should match the real address in the DRA/IEARA record.

To handle this case look in the interrupted records for a XLATEs with a final
real address matching the DRA/IEARA of the record.

If the record is interrupted after the guest real address is sent but before the
host real address is sent, when the record is resumed no more XLATE records are
sent so the above lookup on final real address can not work.
