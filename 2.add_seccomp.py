#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
在不改变 ELF 文件大小的前提下，为 x86_64 Linux ELF 注入 seccomp。

设计目标：
1. 仅修改必要字节（hook 点 8 字节 + stub 字节 + 必要时段头 16 字节）
2. 不扩展文件大小
3. 尽量保持原有行为（stub 执行后跳转回原执行流）

限制：
1. 仅支持 ELF64 little-endian
2. 仅支持 x86_64
3. 支持 No-PIE (ET_EXEC) 与 PIE (ET_DYN)
4. seccomp 黑名单模式使用简化 BPF（按 syscall nr 匹配封禁）
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1

ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 0x3E

PT_LOAD = 1
PF_X = 0x1
SHT_INIT_ARRAY = 14

SYS_SECCOMP_X86_64 = 317
SYS_PRCTL_X86_64 = 157
PR_SET_SECCOMP = 22
SECCOMP_SET_MODE_STRICT = 1
SECCOMP_SET_MODE_FILTER = 2
PR_SET_NO_NEW_PRIVS = 38

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ALLOW = 0x7FFF0000

# x86_64 常见 syscall 名称映射（可按需扩展；未覆盖时可直接传数字）。
SYSCALL_NAME_TO_NR: Dict[str, int] = {
	"read": 0,
	"write": 1,
	"open": 2,
	"close": 3,
	"stat": 4,
	"fstat": 5,
	"lstat": 6,
	"mmap": 9,
	"mprotect": 10,
	"munmap": 11,
	"brk": 12,
	"rt_sigaction": 13,
	"rt_sigprocmask": 14,
	"ioctl": 16,
	"access": 21,
	"pipe": 22,
	"dup": 32,
	"dup2": 33,
	"nanosleep": 35,
	"getpid": 39,
	"socket": 41,
	"connect": 42,
	"accept": 43,
	"sendto": 44,
	"recvfrom": 45,
	"clone": 56,
	"fork": 57,
	"vfork": 58,
	"execve": 59,
	"exit": 60,
	"kill": 62,
	"ptrace": 101,
	"prctl": 157,
	"arch_prctl": 158,
	"chroot": 161,
	"mount": 165,
	"umount2": 166,
	"openat": 257,
	"mkdirat": 258,
	"unlinkat": 263,
	"renameat": 264,
	"faccessat": 269,
	"execveat": 322,
	"openat2": 437,
}

SYSCALL_NR_TO_NAME: Dict[int, str] = {v: k for k, v in SYSCALL_NAME_TO_NR.items()}


@dataclass
class ElfHeader:
	endian: str
	e_type: int
	e_machine: int
	e_entry: int
	e_phoff: int
	e_shoff: int
	e_phentsize: int
	e_phnum: int
	e_shentsize: int
	e_shnum: int
	e_shstrndx: int


@dataclass
class ProgramHeader:
	index: int
	offset_in_file: int
	p_type: int
	p_flags: int
	p_offset: int
	p_vaddr: int
	p_paddr: int
	p_filesz: int
	p_memsz: int
	p_align: int


@dataclass
class SectionHeader:
	index: int
	sh_name: int
	sh_type: int
	sh_flags: int
	sh_addr: int
	sh_offset: int
	sh_size: int
	sh_link: int
	sh_info: int
	sh_addralign: int
	sh_entsize: int


@dataclass
class PatchPlan:
	phdr: ProgramHeader
	inject_off: int
	inject_vaddr: int
	inject_len: int
	hook_off: int
	hook_original_value: int
	hook_label: str
	new_filesz: int
	new_memsz: int
	need_update_phdr_sizes: bool


@dataclass
class SeccompConfig:
	blacklist: List[int]

	@property
	def mode(self) -> str:
		return "blacklist" if self.blacklist else "strict"


class PatchError(Exception):
	pass


def parse_elf_header(data: bytes) -> ElfHeader:
	if len(data) < 64:
		raise PatchError("文件过小，不是有效 ELF")

	if data[:4] != ELF_MAGIC:
		raise PatchError("ELF 魔数错误")

	ei_class = data[4]
	ei_data = data[5]
	if ei_class != ELFCLASS64:
		raise PatchError("仅支持 ELF64")
	if ei_data != ELFDATA2LSB:
		raise PatchError("仅支持 little-endian")

	endian = "<"
	fields = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
	e_type = fields[0]
	e_machine = fields[1]
	e_entry = fields[3]
	e_phoff = fields[4]
	e_shoff = fields[5]
	e_phentsize = fields[8]
	e_phnum = fields[9]
	e_shentsize = fields[10]
	e_shnum = fields[11]
	e_shstrndx = fields[12]

	if e_machine != EM_X86_64:
		raise PatchError("仅支持 x86_64 ELF")
	if e_type not in (ET_EXEC, ET_DYN):
		raise PatchError("仅支持 ET_EXEC(No-PIE) 与 ET_DYN(PIE) ELF")

	return ElfHeader(
		endian=endian,
		e_type=e_type,
		e_machine=e_machine,
		e_entry=e_entry,
		e_phoff=e_phoff,
		e_shoff=e_shoff,
		e_phentsize=e_phentsize,
		e_phnum=e_phnum,
		e_shentsize=e_shentsize,
		e_shnum=e_shnum,
		e_shstrndx=e_shstrndx,
	)


def parse_program_headers(data: bytes, ehdr: ElfHeader) -> List[ProgramHeader]:
	phdrs: List[ProgramHeader] = []
	need_size = ehdr.e_phoff + ehdr.e_phnum * ehdr.e_phentsize
	if need_size > len(data):
		raise PatchError("Program Header Table 越界")

	for i in range(ehdr.e_phnum):
		off = ehdr.e_phoff + i * ehdr.e_phentsize
		fields = struct.unpack_from(ehdr.endian + "IIQQQQQQ", data, off)
		phdrs.append(
			ProgramHeader(
				index=i,
				offset_in_file=off,
				p_type=fields[0],
				p_flags=fields[1],
				p_offset=fields[2],
				p_vaddr=fields[3],
				p_paddr=fields[4],
				p_filesz=fields[5],
				p_memsz=fields[6],
				p_align=fields[7],
			)
		)
	return phdrs


def parse_section_headers(data: bytes, ehdr: ElfHeader) -> List[SectionHeader]:
	shdrs: List[SectionHeader] = []
	if ehdr.e_shoff == 0 or ehdr.e_shnum == 0:
		raise PatchError("缺少 Section Header Table，无法定位 .init_array")

	need_size = ehdr.e_shoff + ehdr.e_shnum * ehdr.e_shentsize
	if need_size > len(data):
		raise PatchError("Section Header Table 越界")

	for i in range(ehdr.e_shnum):
		off = ehdr.e_shoff + i * ehdr.e_shentsize
		fields = struct.unpack_from(ehdr.endian + "IIQQQQIIQQ", data, off)
		shdrs.append(
			SectionHeader(
				index=i,
				sh_name=fields[0],
				sh_type=fields[1],
				sh_flags=fields[2],
				sh_addr=fields[3],
				sh_offset=fields[4],
				sh_size=fields[5],
				sh_link=fields[6],
				sh_info=fields[7],
				sh_addralign=fields[8],
				sh_entsize=fields[9],
			)
		)
	return shdrs


def read_c_string(blob: bytes, offset: int) -> str:
	if offset < 0 or offset >= len(blob):
		return ""
	end = blob.find(b"\x00", offset)
	if end == -1:
		end = len(blob)
	return blob[offset:end].decode("latin-1", errors="ignore")


def find_init_array_section(
	data: bytes, ehdr: ElfHeader, shdrs: List[SectionHeader]
) -> SectionHeader:
	if ehdr.e_shstrndx >= len(shdrs):
		raise PatchError("e_shstrndx 越界")

	shstr = shdrs[ehdr.e_shstrndx]
	shstr_end = shstr.sh_offset + shstr.sh_size
	if shstr_end > len(data):
		raise PatchError("节名字符串表越界")
	shstr_blob = data[shstr.sh_offset:shstr_end]

	by_name: Optional[SectionHeader] = None
	by_type: Optional[SectionHeader] = None
	for sh in shdrs:
		name = read_c_string(shstr_blob, sh.sh_name)
		if name == ".init_array":
			by_name = sh
			break
		if sh.sh_type == SHT_INIT_ARRAY and by_type is None:
			by_type = sh

	target = by_name or by_type
	if target is None:
		raise PatchError("未找到 .init_array")
	if target.sh_size < 8:
		raise PatchError(".init_array 太小，无法改写首项")
	if target.sh_offset + target.sh_size > len(data):
		raise PatchError(".init_array 越界")
	return target


def parse_blacklist_arg(raw: str) -> List[int]:
	"""
	解析用户输入的黑名单字符串。
	支持格式：
	1) 数字: 59,257
	2) 名称: execve,openat
	3) 混合: execve,257
	"""
	raw = raw.strip()
	if not raw:
		return []

	result: List[int] = []
	seen = set()
	for token in raw.split(","):
		t = token.strip().lower()
		if not t:
			continue
		if t.startswith("sys_"):
			t = t[4:]

		nr: Optional[int] = None
		try:
			nr = int(t, 0)
		except ValueError:
			nr = SYSCALL_NAME_TO_NR.get(t)

		if nr is None:
			raise PatchError(f"未知 syscall: {token}，请用数字或受支持名称")
		if nr < 0 or nr > 0xFFFFFFFF:
			raise PatchError(f"syscall 编号越界: {nr}")

		if nr not in seen:
			seen.add(nr)
			result.append(nr)

	if not result:
		raise PatchError("黑名单为空，请至少提供一个 syscall")

	return result


def format_syscall_list(syscalls: List[int]) -> str:
	parts = []
	for nr in syscalls:
		name = SYSCALL_NR_TO_NAME.get(nr)
		if name:
			parts.append(f"{name}({nr})")
		else:
			parts.append(str(nr))
	return ", ".join(parts)


def build_blacklist_filter_blob(syscalls: List[int]) -> bytes:
	"""
	生成简化 seccomp BPF：
	A = syscall_nr
	for s in blacklist:
		if A == s: KILL_PROCESS
	ALLOW

	每条 sock_filter 结构: struct { u16 code; u8 jt; u8 jf; u32 k; }
	"""
	if not syscalls:
		raise PatchError("黑名单模式下，syscall 列表不能为空")

	insns: List[Tuple[int, int, int, int]] = []
	insns.append((0x20, 0, 0, 0))
	for nr in syscalls:
		insns.append((0x15, 0, 1, nr & 0xFFFFFFFF))
		insns.append((0x06, 0, 0, SECCOMP_RET_KILL_PROCESS))
	insns.append((0x06, 0, 0, SECCOMP_RET_ALLOW))

	if len(insns) > 0xFFFF:
		raise PatchError("BPF 指令过多，超出 sock_fprog len 上限")

	blob = bytearray()
	for code, jt, jf, k in insns:
		blob += struct.pack("<HBBI", code, jt, jf, k)
	return bytes(blob)


def make_jump_back_rel32(inject_vaddr: int, cur_off: int, target_vaddr: int) -> bytes:
	"""
	生成 jmp rel32 跳回原执行流。
	PIE 下也可用（同一映像内偏移跳转）。
	"""
	if target_vaddr == 0:
		return b"\xC3"

	next_rip = inject_vaddr + cur_off + 5
	disp = target_vaddr - next_rip
	if disp < -0x80000000 or disp > 0x7FFFFFFF:
		raise PatchError("跳转距离超出 rel32 范围，当前实现不支持")
	return b"\xE9" + struct.pack("<i", disp)


def estimate_stub_len(config: SeccompConfig, has_target: bool) -> int:
	dummy_target = 0x1000 if has_target else 0
	return len(make_seccomp_stub_x86_64(0, dummy_target, config))


def make_seccomp_stub_x86_64(
	inject_vaddr: int, target_vaddr: int, config: SeccompConfig
) -> bytes:
	"""
	生成 seccomp 初始化 stub（strict 或 blacklist）。

	strict:
	  seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL)

	blacklist:
	  seccomp(SECCOMP_SET_MODE_FILTER, 0, &sock_fprog)
	  其中 sock_fprog/filter 内联到 stub 末尾
	"""

	# 保存/恢复关键寄存器，避免 PIE e_entry hook 破坏启动现场（尤其 rdx/rcx/r11）。
	# push: rax, rdi, rsi, rdx, rcx, r11, r10, r8
	SAVE_REGS = b"\x50\x57\x56\x52\x51\x41\x53\x41\x52\x41\x50"
	# pop: r8, r10, r11, rcx, rdx, rsi, rdi, rax
	RESTORE_REGS = b"\x41\x58\x41\x5A\x41\x5B\x59\x5A\x5E\x5F\x58"

	# prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	PRCTL_NO_NEW_PRIVS = (
		b"\xB8" + struct.pack("<I", SYS_PRCTL_X86_64)
		+ b"\xBF" + struct.pack("<I", PR_SET_NO_NEW_PRIVS)
		+ b"\xBE\x01\x00\x00\x00"
		+ b"\x31\xD2"
		+ b"\x45\x31\xD2"
		+ b"\x45\x31\xC0"
		+ b"\x0F\x05"
	)

	if config.mode == "strict":
		code = bytearray()
		code += SAVE_REGS
		code += PRCTL_NO_NEW_PRIVS

		# 先走 seccomp syscall，失败时回退到 prctl(PR_SET_SECCOMP, STRICT)
		code += b"\xB8" + struct.pack("<I", SYS_SECCOMP_X86_64)
		code += b"\xBF" + struct.pack("<I", SECCOMP_SET_MODE_STRICT)
		code += b"\x31\xF6"
		code += b"\x31\xD2"
		code += b"\x0F\x05"
		code += b"\x85\xC0"            # test eax, eax
		code += b"\x79\x19"            # jns +25
		code += b"\xB8" + struct.pack("<I", SYS_PRCTL_X86_64)
		code += b"\xBF" + struct.pack("<I", PR_SET_SECCOMP)
		code += b"\xBE" + struct.pack("<I", SECCOMP_SET_MODE_STRICT)
		code += b"\x31\xD2"
		code += b"\x45\x31\xD2"
		code += b"\x45\x31\xC0"
		code += b"\x0F\x05"

		code += RESTORE_REGS
		code += make_jump_back_rel32(inject_vaddr, len(code), target_vaddr)
		return bytes(code)

	filter_blob = build_blacklist_filter_blob(config.blacklist)
	insn_count = len(filter_blob) // 8

	code = bytearray()
	code += SAVE_REGS
	code += PRCTL_NO_NEW_PRIVS

	# lea r10, [rip + disp32_to_filter]
	lea_off = len(code)
	code += b"\x4C\x8D\x15\x00\x00\x00\x00"

	# sub rsp, 0x10
	code += b"\x48\x83\xEC\x10"
	# mov word ptr [rsp], insn_count
	code += b"\x66\xC7\x04\x24" + struct.pack("<H", insn_count)
	# mov [rsp+8], r10
	code += b"\x4C\x89\x54\x24\x08"

	# seccomp(SECCOMP_SET_MODE_FILTER, 0, rsp)
	code += b"\xB8" + struct.pack("<I", SYS_SECCOMP_X86_64)
	code += b"\xBF" + struct.pack("<I", SECCOMP_SET_MODE_FILTER)
	code += b"\x31\xF6"
	code += b"\x48\x89\xE2"
	code += b"\x0F\x05"
	code += b"\x85\xC0"               # test eax, eax
	code += b"\x79\x1A"               # jns +26

	# fallback: prctl(PR_SET_SECCOMP, FILTER, rsp)
	code += b"\xB8" + struct.pack("<I", SYS_PRCTL_X86_64)
	code += b"\xBF" + struct.pack("<I", PR_SET_SECCOMP)
	code += b"\xBE" + struct.pack("<I", SECCOMP_SET_MODE_FILTER)
	code += b"\x48\x89\xE2"
	code += b"\x45\x31\xD2"
	code += b"\x45\x31\xC0"
	code += b"\x0F\x05"

	# add rsp, 0x10
	code += b"\x48\x83\xC4\x10"
	code += RESTORE_REGS

	# 跳回原执行流
	code += make_jump_back_rel32(inject_vaddr, len(code), target_vaddr)

	# 追加过滤器数据区
	filter_off = len(code)
	code += filter_blob

	# 回填 lea disp32
	rip_after_lea = inject_vaddr + lea_off + 7
	filter_addr = inject_vaddr + filter_off
	disp = filter_addr - rip_after_lea
	if disp < -0x80000000 or disp > 0x7FFFFFFF:
		raise PatchError("过滤器地址位移超出 rel32 范围")
	struct.pack_into("<i", code, lea_off + 3, disp)

	return bytes(code)


def choose_hook_point(
	data: bytes,
	ehdr: ElfHeader,
	shdrs: Optional[List[SectionHeader]],
) -> Tuple[int, int, str]:
	"""
	返回 (hook_off, hook_original_value, hook_label)

	No-PIE: 改写 .init_array[0]
	PIE:    改写 e_entry（避免 .init_array 在 PIE 下的 RELA 覆写问题）
	"""
	if ehdr.e_type == ET_DYN:
		return 24, ehdr.e_entry, "e_entry"

	if shdrs is None:
		raise PatchError("缺少 Section Header，无法定位 .init_array")

	init_array_sec = find_init_array_section(data, ehdr, shdrs)
	hook_off = init_array_sec.sh_offset
	original = struct.unpack_from(ehdr.endian + "Q", data, hook_off)[0]
	return hook_off, original, ".init_array[0]"


def choose_injection_plan(
	data: bytes,
	phdrs: List[ProgramHeader],
	hook_off: int,
	hook_original_value: int,
	hook_label: str,
	stub_len: int,
) -> PatchPlan:
	load_segments = [p for p in phdrs if p.p_type == PT_LOAD]
	load_segments.sort(key=lambda p: p.p_offset)

	if not load_segments:
		raise PatchError("未找到 PT_LOAD 段")

	candidates: List[Tuple[int, int, ProgramHeader, int, int]] = []

	for idx, seg in enumerate(load_segments):
		# 优先在可执行段注入，避免 NX 问题。
		if (seg.p_flags & PF_X) == 0:
			continue

		inject_off = seg.p_offset + seg.p_filesz

		next_off = len(data)
		for n in load_segments[idx + 1 :]:
			if n.p_offset > seg.p_offset:
				next_off = n.p_offset
				break

		if next_off < inject_off:
			continue

		available = next_off - inject_off
		if available < stub_len:
			continue

		# 如果 p_align 非 0，尽量限制在本段对齐单元内，降低重叠风险。
		align_cap = available
		if seg.p_align and seg.p_align > 1:
			boundary = ((inject_off + seg.p_align - 1) // seg.p_align) * seg.p_align
			if boundary > inject_off:
				align_cap = min(align_cap, boundary - inject_off)

		if align_cap < stub_len:
			continue

		new_filesz = seg.p_filesz + stub_len
		new_memsz = max(seg.p_memsz, new_filesz)

		# 额外做一个 vaddr 侧重叠检查（保守）。
		cur_end_vaddr = seg.p_vaddr + new_memsz
		next_vaddr = None
		for n in load_segments[idx + 1 :]:
			if n.p_vaddr > seg.p_vaddr:
				next_vaddr = n.p_vaddr
				break
		if next_vaddr is not None and cur_end_vaddr > next_vaddr:
			continue

		inject_vaddr = seg.p_vaddr + (inject_off - seg.p_offset)

		# 排序偏好：总改动最小（不需要改段头优先），其次选最靠后的空洞。
		need_update_sizes = not (new_filesz <= seg.p_filesz and new_memsz <= seg.p_memsz)
		score = 1 if need_update_sizes else 0
		candidates.append((score, -inject_off, seg, inject_off, inject_vaddr))

	if not candidates:
		raise PatchError("未找到可容纳 seccomp stub 的可执行 PT_LOAD 填充区")

	candidates.sort(key=lambda x: (x[0], x[1]))
	_, _, seg, inject_off, inject_vaddr = candidates[0]

	new_filesz = seg.p_filesz + stub_len
	new_memsz = max(seg.p_memsz, new_filesz)
	need_update_phdr_sizes = new_filesz != seg.p_filesz or new_memsz != seg.p_memsz

	return PatchPlan(
		phdr=seg,
		inject_off=inject_off,
		inject_vaddr=inject_vaddr,
		inject_len=stub_len,
		hook_off=hook_off,
		hook_original_value=hook_original_value,
		hook_label=hook_label,
		new_filesz=new_filesz,
		new_memsz=new_memsz,
		need_update_phdr_sizes=need_update_phdr_sizes,
	)


def apply_patch(
	data: bytes,
	ehdr: ElfHeader,
	plan: PatchPlan,
	config: SeccompConfig,
) -> Tuple[bytes, bytes]:
	out = bytearray(data)
	original = bytes(data)

	stub = make_seccomp_stub_x86_64(
		inject_vaddr=plan.inject_vaddr,
		target_vaddr=plan.hook_original_value,
		config=config,
	)
	if len(stub) != plan.inject_len:
		raise PatchError("内部错误：stub 长度不一致")

	end_off = plan.inject_off + len(stub)
	if end_off > len(out):
		raise PatchError("注入位置越界，无法保持文件大小")

	out[plan.inject_off:end_off] = stub

	# 改写 hook 点 -> stub_vaddr
	struct.pack_into(ehdr.endian + "Q", out, plan.hook_off, plan.inject_vaddr)

	# 必要时修改对应 PT_LOAD 的 p_filesz / p_memsz
	if plan.need_update_phdr_sizes:
		phoff = plan.phdr.offset_in_file
		struct.pack_into(ehdr.endian + "Q", out, phoff + 32, plan.new_filesz)
		struct.pack_into(ehdr.endian + "Q", out, phoff + 40, plan.new_memsz)

	if len(out) != len(original):
		raise PatchError("补丁后文件大小发生变化，这不符合约束")

	return bytes(original), bytes(out)


def calc_diff_stats(a: bytes, b: bytes) -> Tuple[int, List[int]]:
	if len(a) != len(b):
		return abs(len(a) - len(b)), []
	changed = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
	return len(changed), changed


def verify_post_patch(data_before: bytes, data_after: bytes) -> None:
	if len(data_before) != len(data_after):
		raise PatchError("补丁后大小变化，校验失败")
	# 快速检查 ELF 头仍是合法 64-bit LE ELF
	parse_elf_header(data_after)


def patch_elf(
	input_path: str,
	output_path: str,
	config: SeccompConfig,
	dry_run: bool = False,
) -> None:
	with open(input_path, "rb") as f:
		raw = f.read()

	ehdr = parse_elf_header(raw)
	phdrs = parse_program_headers(raw, ehdr)
	shdrs: Optional[List[SectionHeader]] = None
	if ehdr.e_type == ET_EXEC:
		shdrs = parse_section_headers(raw, ehdr)

	hook_off, hook_original_value, hook_label = choose_hook_point(raw, ehdr, shdrs)
	stub_len = estimate_stub_len(config, hook_original_value != 0)
	plan = choose_injection_plan(
		data=raw,
		phdrs=phdrs,
		hook_off=hook_off,
		hook_original_value=hook_original_value,
		hook_label=hook_label,
		stub_len=stub_len,
	)

	stub = make_seccomp_stub_x86_64(
		inject_vaddr=plan.inject_vaddr,
		target_vaddr=plan.hook_original_value,
		config=config,
	)
	if len(stub) != plan.inject_len:
		raise PatchError("内部错误：stub 估算长度与实际长度不一致")

	elf_type_text = "PIE(ET_DYN)" if ehdr.e_type == ET_DYN else "No-PIE(ET_EXEC)"

	print("[+] 目标文件:", input_path)
	print("[+] ELF 类型:", elf_type_text)
	print("[+] e_entry:", hex(ehdr.e_entry))
	print("[+] seccomp 模式:", config.mode)
	if config.mode == "blacklist":
		print("[+] 黑名单 syscall:", format_syscall_list(config.blacklist))
	print("[+] hook 点:", plan.hook_label, "@", hex(plan.hook_off))
	print("[+] hook 原值:", hex(plan.hook_original_value))
	print("[+] 注入段 index:", plan.phdr.index)
	print("[+] 注入文件偏移:", hex(plan.inject_off))
	print("[+] 注入虚拟地址:", hex(plan.inject_vaddr))
	print("[+] stub 长度:", len(stub), "bytes")
	print("[+] 将改写", plan.hook_label, "->", hex(plan.inject_vaddr))

	if plan.need_update_phdr_sizes:
		print(
			"[+] 将更新 PT_LOAD 大小: p_filesz",
			hex(plan.phdr.p_filesz),
			"->",
			hex(plan.new_filesz),
			", p_memsz",
			hex(plan.phdr.p_memsz),
			"->",
			hex(plan.new_memsz),
		)
	else:
		print("[+] 本次不需要修改 PT_LOAD 大小字段")

	if dry_run:
		print("[+] dry-run 模式，不写出文件")
		return

	before, after = apply_patch(raw, ehdr, plan, config)
	verify_post_patch(before, after)

	changed_cnt, changed_idx = calc_diff_stats(before, after)
	print("[+] 实际修改字节数:", changed_cnt)
	if changed_idx:
		print(
			"[+] 最小修改偏移:",
			hex(changed_idx[0]),
			"最大修改偏移:",
			hex(changed_idx[-1]),
		)

	with open(output_path, "wb") as f:
		f.write(after)

	print("[+] 输出文件:", output_path)
	print("[+] 输出大小:", len(after), "bytes (与原文件一致)")


def build_argparser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		description="为 x86_64 ELF 注入 seccomp（支持 No-PIE/PIE，文件大小不变）"
	)
	parser.add_argument("input", help="输入 ELF 路径")
	parser.add_argument("output", nargs="?", help="输出 ELF 路径（默认: 输入名 + .patched）")
	parser.add_argument(
		"--blacklist",
		default="",
		help=(
			"逗号分隔 syscall 黑名单（名称或数字）。"
			"示例: --blacklist execve,openat,59。"
			"不提供时使用 strict 模式。"
		),
	)
	parser.add_argument(
		"--dry-run", action="store_true", help="只分析可行性与改动计划，不写文件"
	)
	return parser


def main() -> int:
	parser = build_argparser()
	args = parser.parse_args()

	input_path = args.input
	output_path = args.output if args.output else input_path + ".patched"

	try:
		blacklist = parse_blacklist_arg(args.blacklist)
		config = SeccompConfig(blacklist=blacklist)
		patch_elf(input_path, output_path, config=config, dry_run=args.dry_run)
		return 0
	except (OSError, PatchError, struct.error) as exc:
		print("[-] 失败:", exc)
		return 1


if __name__ == "__main__":
	sys.exit(main())
