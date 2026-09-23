#!/usr/bin/env python3
"""
What it does:
  1. INFO       arch, entrypoint, sections, segments, version strings
  2. IMPORTS    dynamic symbols (imported/exported functions & objects)
  3. STRINGS    plaintext ASCII / UTF-16LE strings from data sections
  4. ENCRYPTED  high-entropy blobs + cipher brute-force (XOR/add/sub/repeating)
  5. XREF       ADRP+ADD / ADRP+LDR (arm64), LEA/MOV [RIP+disp] (x86_64)
                who references a given data RVA
  6. INT3       scan .text for 0xCC breakpoints / trap instructions
  7. PEHEADER   detect embedded PE (MZ) headers inside the .so
  8. REFLECT    pseudo-reflection: JNI/Java class & method names resolved
                from .rodata string patterns (Lcom/...; Lorg/...; etc)
  9. DISASM     disassemble a window around any RVA (capstone)  10. RESOLVE    RVA/offset dumper: file offset, section+delta, segment perms,
                exact/nearest/next symbol, function start, raw bytes

Usage:
  python decrypt.py libroblox.so                       # full scan
  python decrypt.py libroblox.so --strings-only
  python decrypt.py libroblox.so --xref 0x254DD90
  python decrypt.py libroblox.so --disasm 0x254DD90
  python decrypt.py libroblox.so --int3
  python decrypt.py libroblox.so --pe
  python decrypt.py libroblox.so --reflect
  python decrypt.py libroblox.so --imports
  python decrypt.py libroblox.so --resolve 0x1D52800 0x5854F4C
  python decrypt.py libroblox.so --grep roblox
  python decrypt.py libroblox.so --out C:/dump
"""

import argparse
import json
import math
import os
import re
import struct
import sys
from pathlib import Path

try:
    from capstone import (Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_ARCH_ARM,
                          CS_MODE_ARM, CS_MODE_64, CS_MODE_THUMB)
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

EM_AARCH64 = 0xB7
EM_X86_64 = 0x3E
EM_ARM = 0x28

PT_LOAD = 1
PT_DYNAMIC = 2
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_DYNSYM = 11


def elf_check(data: bytes) -> bool:
    return data[:4] == b"\x7fELF"


def elf_class(data: bytes) -> int:
    """1 = ELF32, 2 = ELF64."""
    return data[4] if elf_check(data) else 0


def elf_machine(data: bytes) -> int:
    return struct.unpack_from("<H", data, 0x12)[0] if elf_check(data) else 0


def elf_entrypoint(data: bytes) -> int:
    if elf_class(data) == 2:
        return struct.unpack_from("<Q", data, 0x18)[0]
    return struct.unpack_from("<I", data, 0x18)[0]


def arch_name(machine: int) -> str:
    return {EM_AARCH64: "arm64", EM_X86_64: "x86_64", EM_ARM: "arm32"}.get(
        machine, f"unknown(0x{machine:x})")


def load_segments(data: bytes):
    """Return list of PT_LOAD segments: (vaddr, off, filesz, memsz, flags)."""
    is64 = elf_class(data) == 2
    if is64:
        e_phoff   = struct.unpack_from("<Q", data, 0x20)[0]
        e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
        e_phnum   = struct.unpack_from("<H", data, 0x38)[0]
    else:
        e_phoff   = struct.unpack_from("<I", data, 0x1C)[0]
        e_phentsize = struct.unpack_from("<H", data, 0x2A)[0]
        e_phnum   = struct.unpack_from("<H", data, 0x2C)[0]

    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if is64:
            p_type  = struct.unpack_from("<I", data, off)[0]
            p_flags = struct.unpack_from("<I", data, off + 4)[0]
            p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 8)
            p_filesz, p_memsz = struct.unpack_from("<QQ", data, off + 32)
        else:
            p_type  = struct.unpack_from("<I", data, off)[0]
            p_offset = struct.unpack_from("<I", data, off + 4)[0]
            p_vaddr  = struct.unpack_from("<I", data, off + 8)[0]
            p_filesz = struct.unpack_from("<I", data, off + 16)[0]
            p_memsz  = struct.unpack_from("<I", data, off + 20)[0]
            p_flags  = struct.unpack_from("<I", data, off + 24)[0]
        if p_type == PT_LOAD:
            segs.append((p_vaddr, p_offset, p_filesz, p_memsz, p_flags))
    return segs


def rva_to_off(data: bytes, rva: int):
    for vaddr, off, filesz, memsz, _ in load_segments(data):
        if vaddr <= rva < vaddr + memsz:
            fo = off + (rva - vaddr)
            if fo < off + filesz:
                return fo
    return None


def off_to_rva(data: bytes, off: int):
    for vaddr, p_off, filesz, _memsz, _f in load_segments(data):
        if p_off <= off < p_off + filesz:
            return vaddr + (off - p_off)
    return None


def load_sections(data: bytes):
    """Return list of dicts: name, type, addr, off, size, entsize, link."""
    is64 = elf_class(data) == 2
    if is64:
        e_shoff     = struct.unpack_from("<Q", data, 0x28)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
        e_shnum     = struct.unpack_from("<H", data, 0x3C)[0]
        e_shstrndx  = struct.unpack_from("<H", data, 0x3E)[0]
    else:
        e_shoff     = struct.unpack_from("<I", data, 0x20)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x2E)[0]
        e_shnum     = struct.unpack_from("<H", data, 0x30)[0]
        e_shstrndx  = struct.unpack_from("<H", data, 0x32)[0]

    if not e_shoff or not e_shnum:
        return []

    def sh_header(o):
        if is64:
            name_off = struct.unpack_from("<I", data, o)[0]
            sh_type = struct.unpack_from("<I", data, o + 4)[0]
            addr = struct.unpack_from("<Q", data, o + 16)[0]
            sec_off = struct.unpack_from("<Q", data, o + 24)[0]
            size = struct.unpack_from("<Q", data, o + 32)[0]
            link = struct.unpack_from("<I", data, o + 40)[0]
            entsize = struct.unpack_from("<Q", data, o + 56)[0]
        else:
            name_off = struct.unpack_from("<I", data, o)[0]
            sh_type = struct.unpack_from("<I", data, o + 4)[0]
            addr = struct.unpack_from("<I", data, o + 12)[0]
            sec_off = struct.unpack_from("<I", data, o + 16)[0]
            size = struct.unpack_from("<I", data, o + 20)[0]
            link = struct.unpack_from("<I", data, o + 24)[0]
            entsize = struct.unpack_from("<I", data, o + 36)[0]
        return name_off, sh_type, addr, sec_off, size, link, entsize

    # find shstrtab
    shstr_off = shstr_size = 0
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        _n, sh_type, _a, sec_off, size, _l, _e = sh_header(o)
        if i == e_shstrndx:
            shstr_off = sec_off
            shstr_size = size
    shstr = data[shstr_off:shstr_off + shstr_size]

    def sec_name(name_off):
        end = shstr.find(b"\x00", name_off)
        return shstr[name_off:end].decode("ascii", "replace")

    out = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name_off, sh_type, addr, sec_off, size, link, entsize = sh_header(o)
        out.append({"name": sec_name(name_off), "type": sh_type,
                    "addr": addr, "off": sec_off, "size": size,
                    "entsize": entsize, "link": link})
    return out


def load_dynamic_symbols(data: bytes, sections):
    """Parse .dynsym + .dynstr -> list of dicts(name, value, size, type, bind, shndx, defined)."""
    dynsym = next((s for s in sections if s["type"] == SHT_DYNSYM), None)
    if not dynsym or dynsym["link"] >= len(sections):
        return []
    dynstr = sections[dynsym["link"]]
    sym_off = dynsym["off"]
    sym_cnt = dynsym["size"] // dynsym["entsize"] if dynsym["entsize"] else 0
    str_off = dynstr["off"]
    str_sz  = dynstr["size"]

    is64 = elf_class(data) == 2
    out = []
    for i in range(sym_cnt):
        o = sym_off + i * dynsym["entsize"]
        if is64:
            st_name  = struct.unpack_from("<I", data, o)[0]
            st_info  = data[o + 4]
            st_shndx = struct.unpack_from("<H", data, o + 6)[0]
            st_value = struct.unpack_from("<Q", data, o + 8)[0]
            st_size  = struct.unpack_from("<Q", data, o + 16)[0]
        else:
            st_name  = struct.unpack_from("<I", data, o)[0]
            st_value = struct.unpack_from("<I", data, o + 4)[0]
            st_size  = struct.unpack_from("<I", data, o + 8)[0]
            st_info  = data[o + 12]
            st_shndx = struct.unpack_from("<H", data, o + 14)[0]
        end = data.find(b"\x00", str_off + st_name, str_off + str_sz)
        name = data[str_off + st_name:end].decode("utf-8", "replace") if end > str_off + st_name else ""
        stype = st_info & 0xF
        sbind = st_info >> 4
        out.append({"name": name, "value": st_value, "size": st_size,
                    "type": stype, "bind": sbind, "shndx": st_shndx,
                    "defined": st_shndx != 0})
    return out


def load_dynamic_entries(data: bytes):
    """Parse PT_DYNAMIC segment -> list of (tag, val)."""
    is64 = elf_class(data) == 2
    e_phoff = struct.unpack_from("<Q" if is64 else "<I", data, 0x20 if is64 else 0x1C)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36 if is64 else 0x2A)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38 if is64 else 0x2C)[0]
    dyn_off = dyn_sz = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if is64:
            p_type = struct.unpack_from("<I", data, off)[0]
            p_offset = struct.unpack_from("<Q", data, off + 8)[0]
            p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        else:
            p_type = struct.unpack_from("<I", data, off)[0]
            p_offset = struct.unpack_from("<I", data, off + 4)[0]
            p_filesz = struct.unpack_from("<I", data, off + 16)[0]
        if p_type == PT_DYNAMIC:
            dyn_off, dyn_sz = p_offset, p_filesz
            break
    if dyn_off is None:
        return []
    entsz = 16 if is64 else 8
    entries = []
    for i in range(dyn_sz // entsz):
        o = dyn_off + i * entsz
        if is64:
            tag, val = struct.unpack_from("<Qq", data, o)
        else:
            tag, val = struct.unpack_from("<Ii", data, o)
        if tag == 0:
            break
        entries.append((tag, val))
    return entries

def _printable_ascii(b: int) -> bool:
    return 0x20 <= b <= 0x7E


def iter_ascii_strings(blob: bytes, base: int, min_len: int):
    start = None
    run = bytearray()
    for i, b in enumerate(blob):
        if _printable_ascii(b):
            if start is None:
                start = i
            run.append(b)
        else:
            if run and len(run) >= min_len:
                yield base + start, start, run.decode("ascii")
            start = None
            run = bytearray()
    if run and len(run) >= min_len:
        yield base + start, start, run.decode("ascii")


def iter_utf16le_strings(blob: bytes, base: int, min_len: int):
    i = 0
    n = len(blob) - 1
    while i < n:
        lo, hi = blob[i], blob[i + 1]
        if 0x20 <= lo <= 0x7E and hi == 0:
            start = i
            chars = []
            while i < n:
                lo, hi = blob[i], blob[i + 1]
                if 0x20 <= lo <= 0x7E and hi == 0:
                    chars.append(chr(lo))
                    i += 2
                else:
                    break
            if len(chars) >= min_len:
                yield base + start, start, "".join(chars)
        else:
            i += 2


def extract_strings(data: bytes, sections, min_len: int, utf16: bool = True):
    out = []
    for sec in sections:
        if sec["type"] != SHT_PROGBITS:
            continue
        if sec["name"] not in (".rodata", ".data.rel.ro", ".data"):
            continue
        blob = data[sec["off"]:sec["off"] + sec["size"]]
        base = sec["addr"]
        for rva, off, text in iter_ascii_strings(blob, base, min_len):
            out.append({"rva": rva, "off": off, "text": text})
        if utf16:
            for rva, off, text in iter_utf16le_strings(blob, base, min_len):
                out.append({"rva": rva, "off": off, "text": text, "utf16": True})
    return out

def block_entropy(block: bytes) -> float:
    if not block:
        return 0.0
    counts = [0] * 256
    for b in block:
        counts[b] += 1
    n = len(block)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def printable_ratio(blob: bytes) -> float:
    if not blob:
        return 0.0
    ok = sum(1 for b in blob if b in (9, 10, 13) or 0x20 <= b <= 0x7E)
    return ok / len(blob)


_WORD_CHARS = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ")
_LOWER_SPACE = set(b"abcdefghijklmnopqrstuvwxyz ")


def word_ratio(blob: bytes) -> float:
    if not blob:
        return 0.0
    return sum(1 for b in blob if b in _WORD_CHARS) / len(blob)


def english_ratio(blob: bytes) -> float:
    if not blob:
        return 0.0
    return sum(1 for b in blob if b in _LOWER_SPACE) / len(blob)


_ENGLISH_FREQ = {
    ord(c): w for c, w in zip(
        "etaoinshrdlucmfwypvbgkjqxz",
        [12.7, 9.1, 8.2, 7.5, 7.0, 6.7, 6.3, 6.1, 6.0, 4.3, 4.0, 2.8,
         2.4, 2.4, 2.2, 2.0, 2.0, 1.9, 1.0, 0.8, 1.5, 0.2, 0.2, 0.1,
         0.1, 0.1])
}

_WORD_TOKEN = None

def clean_word_ratio(blob: bytes) -> float:
    global _WORD_TOKEN
    if _WORD_TOKEN is None:
        import re as _re
        _WORD_TOKEN = _re.compile(rb"[A-Za-z']+")
    toks = _WORD_TOKEN.findall(blob)
    if not toks:
        return 0.0
    return sum(1 for t in toks if t.islower()) / len(toks)


def find_high_entropy_regions(data: bytes, sections, threshold=6.6,
                              min_size=16, block=64):
    cands = []
    for sec in sections:
        if sec["type"] != SHT_PROGBITS or sec["name"] not in (".rodata", ".data.rel.ro", ".data"):
            continue
        blob = data[sec["off"]:sec["off"] + sec["size"]]
        base = sec["addr"]
        runs = []
        cur = None
        for i in range(0, len(blob), block):
            chunk = blob[i:i + block]
            if len(chunk) < 8:
                break
            ent = block_entropy(chunk)
            pr = printable_ratio(chunk)
            if ent >= threshold and pr < 0.6:
                if cur is None:
                    cur = [i, i + len(chunk), ent, ent]
                else:
                    cur[1] = i + len(chunk)
                    cur[2] = min(cur[2], ent)
                    cur[3] = max(cur[3], ent)
            else:
                if cur:
                    runs.append(tuple(cur))
                    cur = None
        if cur:
            runs.append(tuple(cur))
        for start, end, min_e, max_e in runs:
            size = end - start
            if size >= min_size:
                cands.append({"name": sec["name"], "rva": base + start,
                              "off": sec["off"] + start, "size": size,
                              "entropy_min": round(min_e, 3),
                              "entropy_max": round(max_e, 3)})
    return cands


COMMON_KEYS = [
    b"roblox", b"RBX", b"rbx", b"Roblox", b"Luau", b"luau",
    b"\x00\x00\x00\x00", b"\xff\xff\xff\xff",
]


def _xor_with_key(blob: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def guess_repeating_keylen(blob: bytes, max_keylen: int = 32, blocks: int = 4) -> int:
    n = len(blob)
    scores = {}
    for kl in range(2, min(max_keylen, n // blocks) + 1):
        vals = []
        for i in range(blocks - 1):
            a = blob[i * kl:(i + 1) * kl]
            b = blob[(i + 1) * kl:(i + 2) * kl]
            if len(a) == kl and len(b) == kl:
                vals.append(_hamming(a, b) / kl)
        if vals:
            scores[kl] = sum(vals) / len(vals)
    if not scores:
        return 0
    best = min(scores.values())
    tol = best + 0.15
    cand = [kl for kl, s in scores.items() if s <= tol]
    return min(cand) if cand else 0


def solve_repeating_key(blob: bytes, keylen: int) -> bytes:
    key = bytearray()
    for pos in range(keylen):
        col = blob[pos::keylen]
        best_b, best_s = 0, -1e9
        for k in range(256):
            s = 0.0
            for b in col:
                d = b ^ k
                if d == 32:
                    s += 6.0
                elif 97 <= d <= 122:
                    s += _ENGLISH_FREQ.get(d, 0.5)
                elif 65 <= d <= 90:
                    s += _ENGLISH_FREQ.get(d + 32, 0.5) * 0.5
                elif 48 <= d <= 57:
                    s += 0.5
                else:
                    s -= 1.0
            if s > best_s:
                best_s, best_b = s, k
        key.append(best_b)
    return bytes(key)


def _add_with_key(blob: bytes, key: int) -> bytes:
    return bytes((b + key) & 0xFF for b in blob)


def _sub_with_key(blob: bytes, key: int) -> bytes:
    return bytes((b - key) & 0xFF for b in blob)


def try_decrypt_blob(blob: bytes, min_printable=0.92, min_word=0.70):
    if len(blob) < 8:
        return []
    results = []

    for key in range(1, 256):
        dec = _xor_with_key(blob, bytes([key]))
        if printable_ratio(dec) >= min_printable and word_ratio(dec) >= min_word and english_ratio(dec) >= 0.70:
            results.append((f"xor-0x{key:02x}", f"0x{key:02x}", dec, english_ratio(dec)))

    for key in range(1, 256):
        dec = _add_with_key(blob, key)
        if printable_ratio(dec) >= min_printable and word_ratio(dec) >= min_word and english_ratio(dec) >= 0.70:
            results.append((f"add-0x{key:02x}", f"+0x{key:02x}", dec, english_ratio(dec)))
        dec = _sub_with_key(blob, key)
        if printable_ratio(dec) >= min_printable and word_ratio(dec) >= min_word and english_ratio(dec) >= 0.70:
            results.append((f"sub-0x{key:02x}", f"-0x{key:02x}", dec, english_ratio(dec)))

    for key in COMMON_KEYS:
        if len(key) < 2:
            continue
        dec = _xor_with_key(blob, key)
        if printable_ratio(dec) >= min_printable and word_ratio(dec) >= min_word and english_ratio(dec) >= 0.55:
            results.append((f"xor-repeat({key!r})", key.hex(), dec, english_ratio(dec)))

    if 16 <= len(blob) <= 8192:
        kl_guess = guess_repeating_keylen(blob)
        lens = list(range(2, min(32, len(blob) // 4) + 1))
        if kl_guess:
            lens.sort(key=lambda kl: abs(kl - kl_guess))
        best = None
        for kl in lens:
            key = solve_repeating_key(blob, kl)
            dec = _xor_with_key(blob, key)
            end = len(dec)
            while end > 0 and (dec[end - 1] == 0 or not (0x20 <= dec[end - 1] <= 0x7E)):
                end -= 1
            er_trim = english_ratio(dec[:end]) if end >= 8 else 0.0
            if er_trim >= 0.90 and printable_ratio(dec[:end]) >= min_printable:
                if best is None or (er_trim > best[0] + 0.001
                                    or (abs(er_trim - best[0]) <= 0.001 and kl < best[1])):
                    best = (er_trim, kl, key, dec)
        if best:
            er, kl, key, dec = best
            results.append((f"xor-repeat-auto(kl={kl})", key.hex(), dec, er))

    seen = set()
    best = []
    for scheme, key, dec, wr in sorted(results, key=lambda r: -r[3]):
        text = dec.decode("ascii", "replace")
        if text in seen:
            continue
        seen.add(text)
        best.append((scheme, key, dec, wr))
        if len(best) >= 12:
            break
    return best

def find_adrp_refs(data: bytes, rva: int):
    """arm64: find ADRP+ADD / ADRP+LDR sites that resolve to `rva`."""
    if elf_machine(data) != EM_AARCH64:
        return []
    target_page = rva & ~0xFFF
    low12 = rva & 0xFFF
    segs = load_segments(data)
    refs = []
    limit = 0
    for _v, off, filesz, _m, _f in segs:
        limit = max(limit, off + filesz)
    limit = min(limit, len(data) - 8)

    for off in range(0, limit, 4):
        w = struct.unpack_from("<I", data, off)[0]
        if (w & 0x9F000000) != 0x90000000:  # ADRP
            continue
        pc = off_to_rva(data, off)
        if pc is None:
            continue
        immlo = (w >> 29) & 0x3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & 0x100000:
            imm -= 0x200000
        page = (pc & ~0xFFF) + (imm << 12)
        if page != target_page:
            continue
        # check next instruction
        nxt = struct.unpack_from("<I", data, off + 4)[0]
        exact = False
        # ADD Xn, Xn, #imm12
        if (nxt & 0xFF800000) == 0x91000000:
            imm12 = (nxt >> 10) & 0xFFF
            exact = (imm12 == low12)
        # LDR Xt, [Xn, #imm12] (unsigned offset, scale=8 for 64-bit / 4 for 32-bit)
        elif (nxt & 0xFFC00000) == 0xF9400000 or (nxt & 0xFFC00000) == 0xB9400000:
            imm12 = (nxt >> 10) & 0xFFF
            scale = 8 if (nxt >> 30) == 3 else 4
            exact = (imm12 * scale == low12)
        refs.append({"rva": pc, "off": off, "exact": exact})
    return refs


def find_rip_rel_refs(data: bytes, rva: int):
    if elf_machine(data) != EM_X86_64:
        return []
    segs = load_segments(data)
    refs = []
    limit = 0
    for _v, off, filesz, _m, _f in segs:
        limit = max(limit, off + filesz)
    limit = min(limit, len(data) - 7)
    for off in range(0, limit):
        b0 = data[off]
        if not (0x40 <= b0 <= 0x4F):
            continue
        op = data[off + 1]
        if op not in (0x8D, 0x8B):
            continue
        modrm = data[off + 2]
        if (modrm & 0xC7) != 0x05:
            continue
        disp = struct.unpack_from("<i", data, off + 3)[0]
        pc = off_to_rva(data, off)
        if pc is None:
            continue
        target = (pc + 7 + disp) & 0xFFFFFFFFFFFFFFFF
        if target == rva:
            refs.append({"rva": pc, "off": off, "exact": True})
    return refs


def find_refs(data: bytes, rva: int):
    machine = elf_machine(data)
    if machine == EM_AARCH64:
        return find_adrp_refs(data, rva)
    if machine == EM_X86_64:
        return find_rip_rel_refs(data, rva)
    return []

def find_int3_sites(data: bytes, sections):
    """Scan executable sections for int3 (0xCC) / arm64 BRK #0 / arm32 BKPT."""
    machine = elf_machine(data)
    results = []
    for sec in sections:
        if sec["type"] != SHT_PROGBITS:
            continue
        if sec["name"] not in (".text", ".plt", ".init", ".fini"):
            continue
        blob = data[sec["off"]:sec["off"] + sec["size"]]
        base = sec["addr"]
        if machine == EM_X86_64:
            for i, b in enumerate(blob):
                if b == 0xCC:
                    results.append({"section": sec["name"], "rva": base + i,
                                    "off": sec["off"] + i, "insn": "int3 (0xCC)"})
        elif machine == EM_AARCH64:
            for off in range(0, len(blob) - 3, 4):
                w = struct.unpack_from("<I", blob, off)[0]
                if (w & 0xFFE0001F) == 0xD4200000:  # BRK #imm
                    imm = (w >> 5) & 0xFFFF
                    results.append({"section": sec["name"], "rva": base + off,
                                    "off": sec["off"] + off, "insn": f"BRK #{imm}"})
        elif machine == EM_ARM:
            for off in range(0, len(blob) - 1, 2):
                hw = struct.unpack_from("<H", blob, off)[0]
                if hw == 0xBE00:  # BKPT #0 (thumb16)
                    results.append({"section": sec["name"], "rva": base + off,
                                    "off": sec["off"] + off, "insn": "BKPT #0"})
                elif hw & 0xFFF0 == 0xE120:  # BKPT (arm32)
                    results.append({"section": sec["name"], "rva": base + off,
                                    "off": sec["off"] + off, "insn": "BKPT"})
    return results

def find_pe_headers(data: bytes, sections):
    """Scan all sections for 'MZ' + 'PE\\0\\0' signature (embedded PE)."""
    results = []
    scan_ranges = []
    for sec in sections:
        if sec["type"] == SHT_PROGBITS and sec["size"] > 0:
            scan_ranges.append((sec["name"], sec["off"], sec["size"], sec["addr"]))
    for name, off, size, addr in scan_ranges:
        blob = data[off:off + size]
        for m in re.finditer(rb"MZ", blob):
            pos = m.start()
            if pos + 0x40 > len(blob):
                continue
            e_lfanew = struct.unpack_from("<I", blob, pos + 0x3C)[0]
            if e_lfanew < 0x40 or pos + e_lfanew + 4 > len(blob):
                continue
            if blob[pos + e_lfanew:pos + e_lfanew + 4] == b"PE\x00\x00":
                results.append({"section": name, "rva": addr + pos,
                                "off": off + pos, "pe_lfanew": e_lfanew})
    return results

_JNI_CLASS_RE = re.compile(rb"L[a-zA-Z][a-zA-Z0-9_/]*[a-zA-Z0-9];")
_JAVA_PKG_RE = re.compile(rb"(com|org|net|cn)/[a-zA-Z0-9_/]{3,}")
_LUAU_RE = re.compile(rb"(?:local\s+function\s+|function\s+)([a-zA-Z_][a-zA-Z0-9_.:]*)")


def extract_reflection(data: bytes, sections):
    """Extract JNI class descriptors, Java package paths, Luau function names."""
    classes = []
    packages = []
    luau_funcs = []
    seen_cls = set()
    seen_pkg = set()
    seen_lua = set()

    for sec in sections:
        if sec["type"] != SHT_PROGBITS or sec["name"] not in (".rodata", ".data.rel.ro", ".data"):
            continue
        blob = data[sec["off"]:sec["off"] + sec["size"]]
        base = sec["addr"]
        for m in _JNI_CLASS_RE.finditer(blob):
            cls = m.group().decode("ascii", "replace")
            if cls not in seen_cls:
                seen_cls.add(cls)
                classes.append({"rva": base + m.start(), "class": cls})
        for m in _JAVA_PKG_RE.finditer(blob):
            pkg = m.group().decode("ascii", "replace")
            if pkg not in seen_pkg:
                seen_pkg.add(pkg)
                packages.append({"rva": base + m.start(), "package": pkg})
        for m in _LUAU_RE.finditer(blob):
            fn = m.group(1).decode("ascii", "replace")
            if fn not in seen_lua and len(fn) >= 3:
                seen_lua.add(fn)
                luau_funcs.append({"rva": base + m.start(1), "name": fn})
    return classes, packages, luau_funcs

def _guess_function_start(data: bytes, rva: int, window: int = 0x10000):
    """Best effort: nearest preceding arm64 prologue (stp x29,x30 / sub sp)."""
    if elf_machine(data) != EM_AARCH64:
        return None
    start = max(0, (rva - window) & ~3)
    off = rva_to_off(data, start)
    end = rva_to_off(data, rva)
    if off is None or end is None:
        return None
    best = None
    while off <= end:
        w = struct.unpack_from("<I", data, off)[0]
        w2 = struct.unpack_from("<I", data, off + 4)[0]
        if (w & 0xFFC003E0) in (0xA98003E0, 0xA9C003E0) or (
                w == 0xD10003FF and (w2 & 0xFFC003E0) in
                (0xA98003E0, 0xA90003E0, 0xA94003E0)):
            best = start + (off - rva_to_off(data, start))
        off += 4
    return best


def resolve_address(data: bytes, rva: int, sections, symbols):
    """Dump everything known about an RVA: file offset, section+delta,
    segment+perms, exact/nearest/next symbol, function start, raw bytes."""
    result = {"rva": rva, "file_off": None,
              "section": None, "section_offset": None, "section_size": None,
              "segment": None,
              "symbol": None, "symbol_size": None,
              "nearest_symbol": None, "offset_in_symbol": None,
              "next_symbol": None, "next_symbol_gap": None,
              "function_start": None,
              "hex": None, "text": None, "is_string": False}
    result["file_off"] = rva_to_off(data, rva)

    for sec in sections:
        if sec["addr"] and sec["addr"] <= rva < sec["addr"] + sec["size"]:
            result["section"] = sec["name"]
            result["section_offset"] = rva - sec["addr"]
            result["section_size"] = sec["size"]
            break

    rwx = None
    for vaddr, off, filesz, memsz, flags in load_segments(data):
        if vaddr <= rva < vaddr + memsz:
            rwx = (("R" if flags & 4 else "-") +
                   ("W" if flags & 2 else "-") +
                   ("X" if flags & 1 else "-"))
            result["segment"] = {"vaddr": vaddr, "off": off,
                                 "filesz": filesz, "memsz": memsz, "rwx": rwx}
            break

    defined = [s for s in symbols if s["defined"] and s["value"] > 0]
    exact = [s for s in defined if s["value"] == rva]
    if exact:
        result["symbol"] = exact[0]["name"]
        result["symbol_size"] = exact[0]["size"]
    else:
        prev = [s for s in defined if s["value"] <= rva]
        if prev:
            nearest = max(prev, key=lambda s: s["value"])
            result["nearest_symbol"] = nearest["name"]
            result["offset_in_symbol"] = rva - nearest["value"]
            result["symbol_size"] = nearest["size"]
        nxt = [s for s in defined if s["value"] > rva]
        if nxt:
            n = min(nxt, key=lambda s: s["value"])
            result["next_symbol"] = n["name"]
            result["next_symbol_gap"] = n["value"] - rva

    fo = result["file_off"]
    if fo is not None:
        raw = data[fo:fo + 16]
        result["hex"] = " ".join(f"{b:02x}" for b in raw)
        e = data.find(b"\x00", fo, fo + 64)
        if e > fo + 1:
            try:
                t = data[fo:e].decode("ascii")
                if t.isprintable():
                    result["text"] = t
                    result["is_string"] = True
            except Exception:
                pass

    if rwx and "X" in rwx:
        result["function_start"] = _guess_function_start(data, rva)
    return result

def disasm_window(data: bytes, rva: int, before: int = 64, after: int = 128):
    if not HAVE_CAPSTONE:
        return ["capstone not installed"]
    machine = elf_machine(data)
    if machine == EM_AARCH64:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        step = 4
    elif machine == EM_X86_64:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        step = 7
    elif machine == EM_ARM:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        step = 4
    else:
        return ["unsupported arch for disasm"]
    md.detail = False

    start = rva - before * step
    end = rva + after * step
    start = max(0, start)
    so = rva_to_off(data, start)
    eo = rva_to_off(data, end)
    if so is None or eo is None:
        return ["rva outside file-backed code"]
    code = data[so:eo + 1]
    lines = []
    for insn in md.disasm(code, start):
        mark = " <=== " if insn.address == rva else ""
        lines.append(f"  0x{insn.address:08x}  {insn.mnemonic:<8s} {insn.op_str}{mark}")
    return lines

def find_versions(data: bytes, sections):
    found = set()
    for sec in sections:
        if sec["type"] != SHT_PROGBITS or sec["name"] not in (".rodata", ".data.rel.ro"):
            continue
        blob = data[sec["off"]:sec["off"] + sec["size"]]
        for m in re.finditer(rb"(\d+\.\d+\.\d+(?:\.\d+)?)", blob):
            found.add(m.group(1).decode())
    return sorted(found)

def fmt_rva(v):
    return f"0x{v:x}"


def data_at(data: bytes, off: int, size: int):
    if off is None or off < 0 or off + size > len(data):
        return None
    return data[off:off + size]


def write_report(base: Path, info: dict, strings: list, cands: list,
                 refs: list, int3s: list, pes: list,
                 classes: list, packages: list, luau: list,
                 imports: list, symbols: list):
    stem = info["stem"]

    # ---- info.txt ----
    lines = []
    lines.append("=" * 70)
    lines.append("Roblox libroblox.so full decryptor & resolver")
    lines.append("=" * 70)
    lines.append(f"File: {info['file']}")
    lines.append(f"Arch: {info['arch']}  (e_machine=0x{info['machine']:x})")
    lines.append(f"Class: {'ELF64' if info['class'] == 2 else 'ELF32'}")
    lines.append(f"Size: {info['size']:,} bytes")
    lines.append(f"Entrypoint: {fmt_rva(info['entrypoint'])}")
    lines.append(f"Version strings: {', '.join(info['versions']) or 'none found'}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("Sections")
    lines.append("-" * 70)
    for s in info["sections"]:
        lines.append(f"  {s['name']:<20s} 0x{s['addr']:08x}  size={s['size']:>12,}  type={s['type']}")

    lines.append("")
    lines.append("-" * 70)
    lines.append("Segments (PT_LOAD)")
    lines.append("-" * 70)
    for vaddr, off, filesz, memsz, flags in info["segments"]:
        rwx = ""
        if flags & 1: rwx += "X"
        if flags & 2: rwx += "W"
        if flags & 4: rwx += "R"
        lines.append(f"  vaddr=0x{vaddr:08x}  off=0x{off:08x}  filesz={filesz:>12,}  memsz={memsz:>12,}  [{rwx}]")

    lines.append("")
    lines.append("-" * 70)
    lines.append(f"Entrypoint: {fmt_rva(info['entrypoint'])}")
    lines.append("-" * 70)

    lines.append("")
    lines.append("-" * 70)
    lines.append(f"Imports (undefined dynamic symbols): {len(imports)}")
    lines.append("-" * 70)
    for sym in imports[:200]:
        lines.append(f"  {fmt_rva(sym['value'])}  {sym['name']}")
    if len(imports) > 200:
        lines.append(f"  ... and {len(imports) - 200} more")

    lines.append("")
    lines.append("-" * 70)
    lines.append(f"Exported symbols (defined): {len(symbols) - len(imports)}")
    lines.append("-" * 70)
    exports = [s for s in symbols if s["defined"]]
    for sym in exports[:200]:
        lines.append(f"  {fmt_rva(sym['value'])}  {sym['name']}  (size={sym['size']})")
    if len(exports) > 200:
        lines.append(f"  ... and {len(exports) - 200} more")

    if int3s:
        lines.append("")
        lines.append("-" * 70)
        lines.append(f"int3 / BRK / BKPT sites: {len(int3s)}")
        lines.append("-" * 70)
        for it in int3s[:200]:
            lines.append(f"  [{it['section']}] {fmt_rva(it['rva'])}  {it['insn']}")

    if pes:
        lines.append("")
        lines.append("-" * 70)
        lines.append(f"Embedded PE headers: {len(pes)}")
        lines.append("-" * 70)
        for pe in pes:
            lines.append(f"  [{pe['section']}] {fmt_rva(pe['rva'])}  (e_lfanew=0x{pe['pe_lfanew']:x})")

    if classes:
        lines.append("")
        lines.append("-" * 70)
        lines.append(f"JNI/Java classes (reflection): {len(classes)}")
        lines.append("-" * 70)
        for c in classes[:200]:
            lines.append(f"  {fmt_rva(c['rva'])}  {c['class']}")
        if len(classes) > 200:
            lines.append(f"  ... and {len(classes) - 200} more")

    if packages:
        lines.append("")
        lines.append("-" * 70)
        lines.append(f"Java packages: {len(packages)}")
        lines.append("-" * 70)
        for p in packages[:200]:
            lines.append(f"  {fmt_rva(p['rva'])}  {p['package']}")

    if luau:
        lines.append("")
        lines.append("-" * 70)
        lines.append(f"Luau function names: {len(luau)}")
        lines.append("-" * 70)
        for f in luau[:200]:
            lines.append(f"  {fmt_rva(f['rva'])}  {f['name']}")

    (base / f"{stem}.info.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # ---- strings ----
    if strings:
        with open(base / f"{stem}.strings.txt", "w", encoding="utf-8") as f:
            for s in strings:
                f.write(f"0x{s['rva']:08x}  {s['text']}\n")
        with open(base / f"{stem}.strings.json", "w", encoding="utf-8") as f:
            json.dump(strings, f, indent=1, ensure_ascii=False)
    else:
        (base / f"{stem}.strings.txt").write_text("(no strings found)\n")

    # ---- encrypted ----
    md = [f"# Encrypted-blob candidates - {info['file']}\n"]
    if not cands:
        md.append("No high-entropy blobs found.\n")
    for c in cands:
        md.append(f"## {c['name']} @ {fmt_rva(c['rva'])}  (size {c['size']}, "
                  f"entropy {c['entropy_min']}-{c['entropy_max']})\n")
        blob = data_at(info["data"], c["off"], c["size"])
        if blob is None:
            md.append("  (no file bytes)\n")
            continue
        results = try_decrypt_blob(blob)
        if results:
            for scheme, key, dec, pr in results:
                preview = dec[:120].decode("ascii", "replace")
                md.append(f"  - **{scheme}** (score {pr:.2f}): `{preview}`\n")
        else:
            md.append("  - no common-cipher hit - find the decoder via `--xref`\n")
    (base / f"{stem}.encrypted.md").write_text("\n".join(md), encoding="utf-8")

    # ---- xref ----
    if refs:
        rlines = [f"xrefs to {fmt_rva(refs['rva'])}:"]
        for r in refs["refs"]:
            rlines.append(f"  {fmt_rva(r['rva'])}  exact={r['exact']}")
        (base / f"{stem}.xref.txt").write_text("\n".join(rlines) + "\n", encoding="utf-8")

    # ---- symbols.json ----
    with open(base / f"{stem}.symbols.json", "w", encoding="utf-8") as f:
        json.dump(symbols, f, indent=1, ensure_ascii=False)

    # ---- imports.txt ----
    if imports:
        with open(base / f"{stem}.imports.txt", "w", encoding="utf-8") as f:
            for sym in imports:
                f.write(f"{fmt_rva(sym['value'])}  {sym['name']}\n")

    # ---- reflection.json ----
    refl = {"classes": classes, "packages": packages, "luau_functions": luau}
    with open(base / f"{stem}.reflection.json", "w", encoding="utf-8") as f:
        json.dump(refl, f, indent=1, ensure_ascii=False)

    # ---- int3.txt ----
    if int3s:
        with open(base / f"{stem}.int3.txt", "w", encoding="utf-8") as f:
            for it in int3s:
                f.write(f"[{it['section']}] {fmt_rva(it['rva'])}  {it['insn']}\n")

    # ---- pe.txt ----
    if pes:
        with open(base / f"{stem}.pe.txt", "w", encoding="utf-8") as f:
            for pe in pes:
                f.write(f"[{pe['section']}] {fmt_rva(pe['rva'])}  e_lfanew=0x{pe['pe_lfanew']:x}\n")


def main():
    ap = argparse.ArgumentParser(
        prog="decrypt.py",
        description="Roblox libroblox.so full decryptor & resolver")
    ap.add_argument("so", help="path to libroblox.so (or any Roblox .so)")
    ap.add_argument("--min-len", type=int, default=6,
                    help="minimum plaintext string length (default 6)")
    ap.add_argument("--strings-only", action="store_true",
                    help="only dump plaintext strings")
    ap.add_argument("--no-utf16", action="store_true",
                    help="skip UTF-16LE string scan")
    ap.add_argument("--xref", type=lambda s: int(s, 0), default=None,
                    metavar="RVA", help="find code refs to a data address")
    ap.add_argument("--disasm", type=lambda s: int(s, 0), default=None,
                    metavar="RVA", help="disassemble a window around an address")
    ap.add_argument("--resolve", type=lambda s: int(s, 0), default=None,
                    nargs="+", metavar="RVA",
                    help="RVA/offset dumper: file offset, section, segment, symbols, "
                         "function start, bytes (accepts one or more RVAs; a value "
                         "that is a file offset is auto-detected)")
    ap.add_argument("--int3", action="store_true",
                    help="scan for int3/BRK/BKPT breakpoints")
    ap.add_argument("--pe", action="store_true",
                    help="detect embedded PE headers")
    ap.add_argument("--reflect", action="store_true",
                    help="extract JNI/Java/Luau pseudo-reflection")
    ap.add_argument("--imports", action="store_true",
                    help="dump imports & exports")
    ap.add_argument("--grep", type=str, default=None, metavar="TEXT",
                    help="search dumped strings for TEXT")
    ap.add_argument("--decrypt-output", type=str, default=None, metavar="PATH",
                    help="write a new .so with decrypted blobs patched in place")
    ap.add_argument("--ghidra-export", action="store_true",
                    help="write decrypt_<name>.so (Ghidra/IDA-ready copy of the "
                         ".so, with decrypted blobs patched in) next to the reports")
    ap.add_argument("--min-word", type=float, default=0.70,
                    help="min word_ratio for blob patching (default 0.70)")
    ap.add_argument("--out", default=None, help="output directory "
                    "(default: <so dir>/decrypt)")
    ap.add_argument("--entropy-threshold", type=float, default=6.6,
                    help="entropy cutoff for encrypted-blob scan (default 6.6)")
    args = ap.parse_args()

    so_path = Path(args.so)
    if not so_path.exists():
        print(f"[ERR] file not found: {so_path}")
        sys.exit(1)

    print(f"[*] loading {so_path} ...")
    data = so_path.read_bytes()
    if not elf_check(data):
        print("[ERR] not a valid ELF")
        sys.exit(1)

    machine = elf_machine(data)
    eclass = elf_class(data)
    entrypoint = elf_entrypoint(data)
    arch = arch_name(machine)
    print(f"[*] arch: {arch}  class: {'ELF64' if eclass == 2 else 'ELF32'}")
    print(f"[*] entrypoint: {fmt_rva(entrypoint)}")

    sections = load_sections(data)
    segments = load_segments(data)
    symbols = load_dynamic_symbols(data, sections)
    imports = [s for s in symbols if not s["defined"] and s["name"]]
    exports = [s for s in symbols if s["defined"] and s["name"]]
    versions = find_versions(data, sections)
    print(f"[*] sections: {len(sections)}  segments: {len(segments)}")
    print(f"[*] symbols: {len(symbols)} total ({len(imports)} imports, {len(exports)} exports)")
    print(f"[*] version strings in .rodata: {', '.join(versions) or 'none'}")

    info = {
        "file": str(so_path), "stem": so_path.stem, "arch": arch,
        "machine": machine, "class": eclass, "size": so_path.stat().st_size,
        "entrypoint": entrypoint, "versions": versions,
        "sections": sections, "segments": segments,
        "data": data,
    }

    if args.out is not None:
        out_dir = Path(args.out)
    else:
        # default: keep reports next to the .so being analyzed,
        # i.e. inside the versioned Roblox output folder.
        out_dir = so_path.parent / "decrypt"
    out_dir.mkdir(parents=True, exist_ok=True)

    # ---- explicit queries ----
    if args.resolve is not None:
        for value in args.resolve:
            rva = value
            note = ""
            in_seg = any(v <= rva < v + m for v, _o, _f, m, _fl in segments)
            if not in_seg:
                maybe = off_to_rva(data, rva)
                if maybe is not None:
                    note = f"  [file offset -> rva {fmt_rva(maybe)}]"
                    rva = maybe
            res = resolve_address(data, rva, sections, symbols)
            print(f"[*] resolve {fmt_rva(value)}{note}:")
            if res["file_off"] is not None:
                print(f"    file offset    : 0x{res['file_off']:x}")
            else:
                print(f"    file offset    : (bss / not file-backed)")
            if res["section"]:
                print(f"    section        : {res['section']} +0x{res['section_offset']:x} "
                      f"(size 0x{res['section_size']:x})")
            else:
                print(f"    section        : none")
            seg = res["segment"]
            if seg:
                print(f"    segment        : vaddr=0x{seg['vaddr']:x} "
                      f"filesz=0x{seg['filesz']:x} memsz=0x{seg['memsz']:x} "
                      f"[{seg['rwx']}]")
            if res["symbol"]:
                sz = res["symbol_size"] or 0
                print(f"    symbol         : {res['symbol']} (size 0x{sz:x})")
            elif res["nearest_symbol"]:
                sz = res["symbol_size"] or 0
                print(f"    nearest_symbol : {res['nearest_symbol']} "
                      f"(+0x{res['offset_in_symbol']:x}, size 0x{sz:x})")
            else:
                print(f"    nearest_symbol : none")
            if res["next_symbol"]:
                print(f"    next_symbol    : {res['next_symbol']} (gap 0x{res['next_symbol_gap']:x})")
            if res["function_start"] is not None:
                delta = rva - res["function_start"]
                print(f"    function_start : {fmt_rva(res['function_start'])} (+0x{delta:x})")
            if res["hex"]:
                print(f"    bytes          : {res['hex']}")
            if res["text"]:
                print(f"    string         : {res['text'][:60]!r}")
            if seg and "X" in seg["rwx"]:
                print(f"    code preview   :")
                for line in disasm_window(data, rva, before=0, after=3):
                    print(line)
            print()

    if args.xref is not None:
        print(f"[*] scanning for references to {fmt_rva(args.xref)} ...")
        refs = find_refs(data, args.xref)
        print(f"[+] {len(refs)} reference site(s)")
        for r in refs[:50]:
            print(f"      {fmt_rva(r['rva'])}  (file off 0x{r['off']:x})  exact={r['exact']}")
        if len(refs) > 50:
            print(f"      ... and {len(refs) - 50} more")
        write_report(out_dir, info, [], [], {"rva": args.xref, "refs": refs},
                     [], [], [], [], [], [], [])

    if args.disasm is not None:
        print(f"\n[*] disassembly around {fmt_rva(args.disasm)}:")
        for line in disasm_window(data, args.disasm):
            print(line)

    if args.int3:
        print("[*] scanning for int3/BRK/BKPT breakpoints ...")
        int3s = find_int3_sites(data, sections)
        print(f"[+] {len(int3s)} breakpoint site(s)")
        for it in int3s[:50]:
            print(f"      [{it['section']}] {fmt_rva(it['rva'])}  {it['insn']}")

    if args.pe:
        print("[*] scanning for embedded PE headers ...")
        pes = find_pe_headers(data, sections)
        print(f"[+] {len(pes)} embedded PE header(s)")
        for pe in pes:
            print(f"      [{pe['section']}] {fmt_rva(pe['rva'])}  e_lfanew=0x{pe['pe_lfanew']:x}")

    if args.reflect:
        print("[*] extracting JNI/Java/Luau pseudo-reflection ...")
        classes, packages, luau = extract_reflection(data, sections)
        print(f"[+] {len(classes)} JNI classes, {len(packages)} packages, {len(luau)} Luau funcs")
        for c in classes[:20]:
            print(f"      {fmt_rva(c['rva'])}  {c['class']}")
        if len(classes) > 20:
            print(f"      ... and {len(classes) - 20} more")

    if args.imports:
        print(f"[*] imports ({len(imports)}):")
        for sym in imports[:100]:
            print(f"      {sym['name']}")
        if len(imports) > 100:
            print(f"      ... and {len(imports) - 100} more")
        print(f"\n[*] exports ({len(exports)}):")
        for sym in exports[:100]:
            print(f"      {fmt_rva(sym['value'])}  {sym['name']}")
        if len(exports) > 100:
            print(f"      ... and {len(exports) - 100} more")

    if args.grep is not None:
        print(f"[*] extracting strings and searching for {args.grep!r} ...")
        strings = extract_strings(data, sections, args.min_len,
                                  utf16=not args.no_utf16)
        needle = args.grep.lower()
        hits = [s for s in strings if needle in s["text"].lower()]
        print(f"[+] {len(hits)} match(es)")
        for s in hits[:200]:
            print(f"      0x{s['rva']:08x}  {s['text'][:110]}")
        if len(hits) > 200:
            print(f"      ... and {len(hits) - 200} more")
        if hits:
            print(f"[+] hint: run --xref 0x{hits[0]['rva']:x} to find the code that uses it")
        return

    if args.strings_only:
        print(f"[*] extracting plaintext strings (min {args.min_len}) ...")
        strings = extract_strings(data, sections, args.min_len, utf16=not args.no_utf16)
        print(f"[+] {len(strings)} strings -> {out_dir / (info['stem'] + '.strings.txt')}")
        write_report(out_dir, info, strings, [], None, [], [], [], [], [], [], [])
        return

    # ---- full scan ----
    print(f"[*] extracting plaintext strings (min {args.min_len}) ...")
    strings = extract_strings(data, sections, args.min_len, utf16=not args.no_utf16)
    print(f"[+] {len(strings)} plaintext strings")

    print(f"[*] scanning for high-entropy (encrypted?) blobs ...")
    cands = find_high_entropy_regions(data, sections,
                                      threshold=args.entropy_threshold)
    print(f"[+] {len(cands)} candidate blob(s)")

    print(f"[*] attempting cipher brute-force on candidates ...")
    hits = 0
    for c in cands[:200]:
        blob = data_at(data, c["off"], c["size"])
        if blob is None:
            continue
        results = try_decrypt_blob(blob)
        if results:
            hits += 1
            scheme, key, dec, pr = results[0]
            preview = dec[:100].decode("ascii", "replace")
            print(f"    {fmt_rva(c['rva'])} [{c['name']}] {c['size']}B  "
                  f"-> {scheme}  `{preview}`")
    print(f"[+] {hits} blob(s) decodable with common ciphers")

    print(f"[*] scanning for int3/BRK/BKPT breakpoints ...")
    int3s = find_int3_sites(data, sections)
    print(f"[+] {len(int3s)} breakpoint site(s)")

    print(f"[*] scanning for embedded PE headers ...")
    pes = find_pe_headers(data, sections)
    print(f"[+] {len(pes)} embedded PE header(s)")

    print(f"[*] extracting JNI/Java/Luau pseudo-reflection ...")
    classes, packages, luau = extract_reflection(data, sections)
    print(f"[+] {len(classes)} JNI classes, {len(packages)} packages, {len(luau)} Luau funcs")

    if args.decrypt_output or args.ghidra_export:
        # Destination: explicit --decrypt-output wins, otherwise
        # decrypt_<name>.so next to the reports (Ghidra / IDA ready).
        if args.decrypt_output:
            out_path = Path(args.decrypt_output)
        else:
            out_path = out_dir / f"decrypt_{so_path.name}"
        print(f"[*] building decrypted .so -> {out_path} ...")
        patched = bytearray(data)
        patched_count = 0
        for c in cands[:500]:
            blob = data_at(data, c["off"], c["size"])
            if blob is None:
                continue
            results = try_decrypt_blob(blob)
            if not results:
                continue
            scheme, key, dec, wr = results[0]
            if wr < args.min_word:
                continue
            if len(dec) != len(blob):
                continue
            patched[c["off"]:c["off"] + len(dec)] = dec
            patched_count += 1
            print(f"    patched {fmt_rva(c['rva'])} [{c['name']}] {c['size']}B "
                  f"-> {scheme} (word {wr:.2f})")
        out_path.write_bytes(bytes(patched))
        print(f"[+] wrote {out_path} ({patched_count} blob(s) patched, "
              f"{len(data):,} bytes, byte-for-byte layout-preserving copy)")
        if args.ghidra_export:
            print(f"    import into Ghidra: File > Import File... > {out_path}")
            print(f"    (ELF64 {arch}; language auto-detects as AArch64 little-endian)")

    write_report(out_dir, info, strings, cands, None,
                 int3s, pes, classes, packages, luau, imports, symbols)
    print(f"\n[*] reports written to {out_dir}")
    print(f"      {info['stem']}.info.txt / .strings.txt / .strings.json / .encrypted.md")
    print(f"      {info['stem']}.symbols.json / .imports.txt / .reflection.json")
    if int3s:
        print(f"      {info['stem']}.int3.txt")
    if pes:
        print(f"      {info['stem']}.pe.txt")
    if args.ghidra_export or args.decrypt_output:
        print(f"      decrypt_{so_path.name}  (Ghidra/IDA importable)")
    print(f"[*] done")


if __name__ == "__main__":
    main()
