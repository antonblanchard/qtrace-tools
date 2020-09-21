#!/usr/bin/python3

# Parse the output of qtdis and produce some statistics
#
# The tool takes qtrace output annotated with symbols, ie:
#
# qtdis -e vmlinux testcase.qt | ./qtrace_statistics.py

import re
import sys
import operator
import collections

class statistics:
	exception_lookup = {
		0x100: "System Reset",
		0x200: "Machine Check",
		0x300: "Data Storage",
		0x380: "Data Segment",
		0x400: "Instruction Storage",
		0x480: "Instruction Segment",
		0x500: "External",
		0x600: "Alignment",
		0x700: "Program",
		0x800: "Floating-Point Unavailable",
		0x900: "Decrementer",
		0x980: "Hypervisor Decrementer",
		0xa00: "Directed Privileged Doorbell",
		0xb00: "0xB00 Reserved",
		0xc00: "System Call",
		0xd00: "Trace",
		0xe00: "Hypervisor Data Storage",
		0xe20: "Hypervisor Instruction Storage",
		0xe40: "Hypervisor Emulation Assistance",
		0xe60: "Hypervisor Maintenance",
		0xe80: "Directed Hypervisor Doorbell",
		0xea0: "Hypervisor Virtualization",
		0xec0: "0xec0 Reserved",
		0xee0: "0xee0 Reserved",
		0xf00: "Performance Monitor",
		0xf20: "Vector Unavailable",
		0xf40: "VSX Unavailable",
		0xf60: "Facility Unavailable",
		0xf80: "Hypervisor Facility Unavailable",
		0xfa0: "0xfa0 Reserved",
		0xfc0: "0xfc0 Reserved",
		0xfe0: "0xfe0 Reserved",
	}


	def __init__(self):
		self.idle = 0
		self.system = 0
		self.user = 0
		self.opal = 0
		self.context_switches = 0
		self.exceptions = collections.defaultdict(int)
		self.system_calls = collections.defaultdict(int)

		self.__in_system_call_entry = False
		self.__system_call_branch = False


	def is_exception_entry(self, addr):
		if ((addr & 0xfffffffffffff000) != 0xc000000000004000) and ((addr & 0xfffffffffffff000) != 0x0000000000000000):
			return False

		exception = (addr & 0xfff)
		if exception in self.exception_lookup:
			return True

		return False


	def parse_one(self, addr, insn, function_name):
		if "snooze_loop" in function_name:
			self.idle = self.idle + 1

		if (addr >> 60) == 0xc:
			self.system = self.system + 1
		elif (addr & 0xFFFFFFFFFF000000) == 0x0000000030000000:
			self.opal = self.opal + 1
		else:
			self.user = self.user + 1

		if "__switch_to" in function_name and "mflr" in insn:
			self.context_switches = self.context_switches + 1

		if self.is_exception_entry(addr):
			exception = (addr & 0xfff)

			self.exceptions[exception] = self.exceptions[exception] + 1

			if exception == 0xc00:
				self.__in_system_call_entry = True


		if self.__system_call_branch:
			self.system_calls[function_name] = self.system_calls[function_name] + 1

			self.__system_call_branch = False

		if self.__in_system_call_entry:
			if insn == "bctrl":
				self.__system_call_branch = True
				self.__in_system_call_entry = False


	def print_statistics(self):
		total = self.system + self.user
		if total == 0:
			return

		print("%-30s%10d" % ("total instructions", total))
		print("%-30s%13.2f%%" % ("user", 100.0 * self.user / total))
		print("%-30s%13.2f%%" % ("opal", 100.0 * self.opal / total))
		print("%-30s%13.2f%%" % ("system", 100.0 * (self.system - self.idle) / total))
		print("%-30s%13.2f%%" % ("idle", 100.0 * self.idle / total))

		print("\n%-30s%10d" % ('Context switches', self.context_switches))

		print("\nExceptions:")

		for (exception, count) in sorted(self.exceptions.items(), key=operator.itemgetter(1), reverse=True):
			print("%-30s%10d" % (self.exception_lookup[exception], count))

		print("\nSystem calls:")

		for (system_call, count) in sorted(self.system_calls.items(), key=operator.itemgetter(1), reverse=True):
			print("%-30s%10d" % (system_call, count))


r_sym = re.compile("^([\dA-Fa-f]+)\s+<([\S]+)>\s+(.*)$")
r_no_sym = re.compile("^([\dA-Fa-f]+)\s+(.*)$")

if len(sys.argv) == 1:
	f = sys.stdin
elif len(sys.argv) == 2:
	f = open(sys.argv[1], 'r')
else:
	print("Usage: statistics.py [filename]")
	sys.exit(1)

s = statistics()

for line in f:
	m = r_sym.match(line)
	if m:
		addr = int(m.group(1), 16)
		function_name = m.group(2)
		function_name = function_name.split('+')[0]
		function_name = function_name.replace('sys_', '')
		function_name = function_name.replace('SyS_', '')
		insn = m.group(3)
	else:
		m = r_no_sym.match(line)
		if m:
			addr = int(m.group(1), 16)
			function_name = ""
			insn = m.group(2)
		else:
			print("ERROR parsing line")
			print(line)
			sys.exit(1)

	s.parse_one(addr, insn, function_name)


s.print_statistics()
