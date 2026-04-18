#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Union


ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1

ET_EXEC = 2
ET_DYN = 3
EM_X86_64 = 0x3E

PT_LOAD = 1
PF_X = 0x1


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


class PatchError(Exception):
	pass


def parse_elf_header(data: bytes) -> ElfHeader:
	if len(data) < 64:
		raise PatchError("文件过小，不是有效 ELF")
	if data[:4] != ELF_MAGIC:
		raise PatchError("ELF 魔数错误")
	if data[4] != ELFCLASS64:
		raise PatchError("仅支持 ELF64")
	if data[5] != ELFDATA2LSB:
		raise PatchError("仅支持 little-endian ELF")

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
		raise PatchError("仅支持 ET_EXEC/ET_DYN")

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
	need_size = ehdr.e_phoff + ehdr.e_phnum * ehdr.e_phentsize
	if need_size > len(data):
		raise PatchError("Program Header Table 越界")

	phdrs: List[ProgramHeader] = []
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
	if ehdr.e_shoff == 0 or ehdr.e_shnum == 0:
		raise PatchError("缺少 Section Header Table，无法校验 .text")

	need_size = ehdr.e_shoff + ehdr.e_shnum * ehdr.e_shentsize
	if need_size > len(data):
		raise PatchError("Section Header Table 越界")

	shdrs: List[SectionHeader] = []
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
	if end < 0:
		end = len(blob)
	return blob[offset:end].decode("latin-1", errors="ignore")


def build_section_name_map(
	data: bytes,
	ehdr: ElfHeader,
	shdrs: List[SectionHeader],
) -> Dict[str, SectionHeader]:
	if ehdr.e_shstrndx >= len(shdrs):
		raise PatchError("e_shstrndx 越界")

	shstr = shdrs[ehdr.e_shstrndx]
	shstr_end = shstr.sh_offset + shstr.sh_size
	if shstr_end > len(data):
		raise PatchError("节名字符串表越界")
	shstr_blob = data[shstr.sh_offset:shstr_end]

	out: Dict[str, SectionHeader] = {}
	for sh in shdrs:
		name = read_c_string(shstr_blob, sh.sh_name)
		if name:
			out[name] = sh
	return out


def find_exec_segment_containing_va(phdrs: List[ProgramHeader], va: int) -> ProgramHeader:
	for seg in phdrs:
		if seg.p_type != PT_LOAD:
			continue
		if (seg.p_flags & PF_X) == 0:
			continue
		start = seg.p_vaddr
		end = seg.p_vaddr + seg.p_memsz
		if start <= va < end:
			return seg
	raise PatchError("patch 点不在可执行 PT_LOAD 的 VA 范围内")


def vaddr_to_offset(
	phdrs: List[ProgramHeader],
	vaddr: int,
	*,
	executable_only: bool,
) -> Optional[int]:
	for seg in phdrs:
		if seg.p_type != PT_LOAD:
			continue
		if executable_only and (seg.p_flags & PF_X) == 0:
			continue
		start = seg.p_vaddr
		end = seg.p_vaddr + seg.p_filesz
		if start <= vaddr < end:
			return seg.p_offset + (vaddr - seg.p_vaddr)
	return None


def offset_to_vaddr(
	phdrs: List[ProgramHeader],
	offset: int,
	*,
	executable_only: bool,
) -> Optional[int]:
	for seg in phdrs:
		if seg.p_type != PT_LOAD:
			continue
		if executable_only and (seg.p_flags & PF_X) == 0:
			continue
		start = seg.p_offset
		end = seg.p_offset + seg.p_filesz
		if start <= offset < end:
			return seg.p_vaddr + (offset - seg.p_offset)
	return None


def find_zero_run(blob: Union[bytes, bytearray], start: int, end: int, need: int) -> Optional[int]:
	if need <= 0:
		return start
	if start < 0:
		start = 0
	if end > len(blob):
		end = len(blob)
	if start >= end or end - start < need:
		return None

	run_start = -1
	run_len = 0
	for idx in range(start, end):
		if blob[idx] == 0:
			if run_start < 0:
				run_start = idx
			run_len += 1
			if run_len >= need:
				return run_start
		else:
			run_start = -1
			run_len = 0
	return None


def parse_insert_code(raw: Union[str, bytes, bytearray]) -> bytes:
	if isinstance(raw, (bytes, bytearray)):
		if not raw:
			raise PatchError("insert_code 不能为空")
		return bytes(raw)

	text = raw.strip()
	if not text:
		raise PatchError("insert_code 不能为空")

	normalized = text.replace(" ", "").replace("\t", "").replace("\n", "").replace(",", "")
	normalized = normalized.replace("\\x", "").replace("\\X", "")
	normalized = normalized.replace("0x", "").replace("0X", "")

	if not normalized:
		raise PatchError("insert_code 解析后为空")
	if len(normalized) % 2 != 0:
		raise PatchError("insert_code 必须是偶数个十六进制字符")

	try:
		code = bytes.fromhex(normalized)
	except ValueError as exc:
		raise PatchError("insert_code 不是有效十六进制字节串") from exc

	if not code:
		raise PatchError("insert_code 不能为空")
	return code


def pack_rel32_jmp(src_va: int, dst_va: int) -> bytes:
	rel = dst_va - (src_va + 5)
	if rel < -0x80000000 or rel > 0x7FFFFFFF:
		raise PatchError("rel32 跳转越界")
	return b"\xE9" + struct.pack("<i", rel)


def calc_overwrite_len(patch_va: int, code: bytes) -> int:
	if not code:
		raise PatchError("补丁点附近无可反汇编字节")

	try:
		from capstone import CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, Cs
		from capstone.x86_const import X86_REG_RIP
	except ImportError as exc:
		raise PatchError("缺少 capstone 依赖，请先执行: pip install capstone") from exc

	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.detail = True

	overwrite_len = 0
	seen = False
	for insn in md.disasm(code, patch_va):
		seen = True
		for op in insn.operands:
			if op.type == CS_OP_MEM and op.mem.base == X86_REG_RIP:
				raise PatchError(
					f"发现 RIP-relative 内存操作，不支持搬运: 0x{insn.address:x} {insn.mnemonic} {insn.op_str}"
				)
		overwrite_len += insn.size
		if overwrite_len >= 5:
			return overwrite_len

	if not seen:
		raise PatchError("反汇编失败：未解析到任何指令")
	raise PatchError("反汇编不足以覆盖 5 字节")


def patch_elf_x64_trampoline(
	file_path: str,
	patch_pos: int,
	insert_code: Union[str, bytes, bytearray],
	output_path: Optional[str] = None,
	*,
	pos_is_va: bool = True,
	max_disasm_scan: int = 64,
) -> Dict[str, Union[bool, str, int]]:
	if patch_pos < 0:
		raise PatchError("patch_pos 不能为负数")
	if max_disasm_scan <= 0:
		raise PatchError("max_disasm_scan 必须大于 0")

	insert = parse_insert_code(insert_code)
	in_path = Path(file_path)
	original = in_path.read_bytes()
	blob = bytearray(original)

	ehdr = parse_elf_header(original)
	phdrs = parse_program_headers(original, ehdr)
	shdrs = parse_section_headers(original, ehdr)
	section_map = build_section_name_map(original, ehdr, shdrs)

	text_sec = section_map.get(".text")
	if text_sec is None:
		raise PatchError(".text not found")
	text_end_off = text_sec.sh_offset + text_sec.sh_size
	if text_end_off > len(blob):
		raise PatchError(".text 越界")

	if pos_is_va:
		patch_va = patch_pos
		patch_off = vaddr_to_offset(phdrs, patch_va, executable_only=True)
		if patch_off is None:
			raise PatchError("patch 点不在可执行且 file-backed 的 PT_LOAD")
	else:
		patch_off = patch_pos
		patch_va = offset_to_vaddr(phdrs, patch_off, executable_only=True)
		if patch_va is None:
			raise PatchError("patch offset 不在可执行且 file-backed 的 PT_LOAD")

	if patch_off + 16 > len(blob):
		raise PatchError("patch_pos 非法或越界")

	exec_seg = find_exec_segment_containing_va(phdrs, patch_va)
	seg_start = exec_seg.p_offset
	seg_end = exec_seg.p_offset + exec_seg.p_filesz
	if not (seg_start <= patch_off < seg_end):
		raise PatchError("patch 点不在同一可执行 PT_LOAD 的 file-backed 范围内")

	scan_end = min(len(blob), patch_off + max_disasm_scan)
	overwrite_len = calc_overwrite_len(patch_va, bytes(blob[patch_off:scan_end]))
	if patch_off + overwrite_len > len(blob):
		raise PatchError("overwrite_len 导致写越界")

	stolen = bytes(blob[patch_off : patch_off + overwrite_len])
	cave_need = len(stolen) + len(insert) + 5

	cave_off = find_zero_run(blob, max(text_end_off, seg_start), seg_end, cave_need)
	warning = ""
	if cave_off is None:
		fallback_start = max(patch_off + overwrite_len, seg_start)
		cave_off = find_zero_run(blob, fallback_start, seg_end, cave_need)
		if cave_off is not None:
			warning = "code cave found in fallback search range"

	if cave_off is None:
		raise PatchError("cannot find enough code cave bytes")

	cave_va = offset_to_vaddr(phdrs, cave_off, executable_only=True)
	if cave_va is None:
		raise PatchError("无法将 cave 偏移映射到可执行 VA")

	jump_back = pack_rel32_jmp(
		src_va=cave_va + len(stolen) + len(insert),
		dst_va=patch_va + overwrite_len,
	)
	cave_payload = stolen + insert + jump_back

	if cave_off + len(cave_payload) > seg_end:
		raise PatchError("cave payload 超出可执行段 file-backed 范围")

	blob[cave_off : cave_off + len(cave_payload)] = cave_payload

	jump_to_cave = pack_rel32_jmp(src_va=patch_va, dst_va=cave_va)
	patch_bytes = jump_to_cave + b"\x90" * (overwrite_len - 5)
	blob[patch_off : patch_off + overwrite_len] = patch_bytes

	out_path = output_path if output_path else str(in_path) + ".patched"
	out_data = bytes(blob)
	if len(out_data) != len(original):
		raise PatchError("补丁后文件大小发生变化，这不符合约束")

	Path(out_path).write_bytes(out_data)

	return {
		"ok": True,
		"input_file": str(in_path),
		"output_file": str(out_path),
		"patch_va": hex(patch_va),
		"patch_offset": hex(patch_off),
		"overwrite_len": overwrite_len,
		"cave_va": hex(cave_va),
		"cave_offset": hex(cave_off),
		"cave_size_used": len(cave_payload),
		"warning": warning,
	}


def build_argparser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="x86_64 ELF trampoline patcher")
	parser.add_argument("file_path", help="输入 ELF 路径")
	parser.add_argument("patch_pos", help="补丁位置，支持十进制或 0x")
	parser.add_argument("insert_code", help="插入机器码（5058 或 \\x50\\x58）")
	parser.add_argument("-o", "--output", dest="output_path", default=None, help="输出路径")
	parser.add_argument(
		"--offset-mode",
		action="store_true",
		help="将 patch_pos 解释为文件偏移（默认按 VA 解释）",
	)
	parser.add_argument(
		"--max-scan",
		dest="max_disasm_scan",
		type=int,
		default=64,
		help="补丁点附近反汇编窗口（默认 64）",
	)
	return parser


def main() -> int:
	parser = build_argparser()
	args = parser.parse_args()

	try:
		patch_pos = int(args.patch_pos, 0)
	except ValueError:
		print("[-] 失败: patch_pos 必须是整数（支持十进制或 0x）", file=sys.stderr)
		return 1

	try:
		result = patch_elf_x64_trampoline(
			file_path=args.file_path,
			patch_pos=patch_pos,
			insert_code=args.insert_code,
			output_path=args.output_path,
			pos_is_va=(not args.offset_mode),
			max_disasm_scan=args.max_disasm_scan,
		)
		print(json.dumps(result, ensure_ascii=False, indent=2))
		return 0
	except (PatchError, OSError, struct.error) as exc:
		print(f"[-] 失败: {exc}", file=sys.stderr)
		return 1


if __name__ == "__main__":
	sys.exit(main())
