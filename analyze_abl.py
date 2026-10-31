#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_abl.py —— ABL（Android Bootloader）镜像静态核查工具

用途
    针对网上流传的"fastboot oem unlock 堆溢出 → 强制解锁 BL"说法，
    在**自己的电脑上**离线检查一份 abl 镜像，回答三个具体问题：

      1. 镜像里到底有没有那条被指认的 `ldr w8,[x24,#-0x14] / add w0,w8,#4`？
         它的真实机器码解码出来是什么？
      2. 有没有从全局标志位读取解锁状态（ldrb）的指令？算出来的目标地址是多少？
      3. 传说中引用了 "oem unlock"/"unlock" 字符串的代码在哪（用来定位处理函数）？

    **本工具不连接手机、不发送任何 USB 数据、不修改任何分区。**
    它只读文件。

依赖
    仅 Python 3.8+ 标准库。capstone 不是必需的（见 docs/findings.md 说明）。

用法
    python analyze_abl.py abl_raw.img
    python analyze_abl.py abl_raw.img --json report.json --verbose
    python analyze_abl.py abl_raw.img --base 0x9fc00000     # 裸二进制时手工指定加载基址
    python analyze_abl.py --demo                            # 用内置合成样本演示
    python analyze_abl.py --demo elf -v

退出码
    0  分析完成（无论结论是"发现"还是"未发现"）
    2  输入文件无法解析 / 不存在
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import lzma
import os
import struct
import sys
import textwrap

MAX_IMAGE = 128 * 1024 * 1024
MAX_DECOMP = 256 * 1024 * 1024

# 帖子里出现的四个"传说地址"
CLAIMED_ADDRS = {
    0xD99D5: "酷安帖代码里的默认回退地址 target_global_addr = 0xd99d5",
    0xD99D7: "GitHub README 里写的 0xd99d7",
    0x99DD7D: "GitHub 版 gen_payload.py 里的 0x99dd7d",
    0x40000000: "帖子里写死的 shellcode 落点 SHELLCODE_ADDR",
}


# --------------------------------------------------------------------------
# 镜像加载 / 解包
# --------------------------------------------------------------------------
class Image:
    def __init__(self, raw: bytes, fmt: str, notes: list, elf: dict | None = None):
        self.raw = raw
        self.fmt = fmt
        self.notes = notes
        self.elf = elf
        self.regions: list = []  # [{'name','off','va','size'}]
        self._build_regions()

    def _build_regions(self):
        if self.elf and self.elf["segments"]:
            for i, s in enumerate(self.elf["segments"]):
                self.regions.append(
                    {
                        "name": "PT_LOAD[%d]%s"
                        % (i, "x" if s["flags"] & 1 else ""),
                        "off": s["off"],
                        "va": s["vaddr"],
                        "size": min(s["filesz"], len(self.raw) - s["off"]),
                        "exec": bool(s["flags"] & 1),
                    }
                )
        else:
            self.regions.append(
                {"name": "raw", "off": 0, "va": 0, "size": len(self.raw), "exec": True}
            )

    # -- 地址映射 --------------------------------------------------------
    def off_to_va(self, off: int):
        for r in self.regions:
            if r["off"] <= off < r["off"] + r["size"]:
                return r["va"] + (off - r["off"])
        return None

    def va_to_off(self, va: int):
        for r in self.regions:
            if r["va"] <= va < r["va"] + r["size"]:
                return r["off"] + (va - r["va"])
        return None

    def contains(self, va: int) -> bool:
        return self.va_to_off(va) is not None

    def rebase(self, base: int):
        """裸二进制：把所有 region 的 va 平移到 base。"""
        for r in self.regions:
            r["va"] += base
            r["off"] = r["off"]
        return self


def _elf_ok(raw: bytes) -> bool:
    return raw[:4] == b"\x7fELF"


def parse_elf(raw: bytes) -> dict:
    if len(raw) < 64:
        raise ValueError("文件太短，不像 ELF")
    if raw[4] != 2 or raw[5] != 1:
        raise ValueError("只支持 ELF64 / 小端")
    e_machine = struct.unpack_from("<H", raw, 18)[0]
    e_entry = struct.unpack_from("<Q", raw, 24)[0]
    e_phoff = struct.unpack_from("<Q", raw, 32)[0]
    e_phentsize = struct.unpack_from("<H", raw, 54)[0]
    e_phnum = struct.unpack_from("<H", raw, 56)[0]
    segs = []
    for i in range(e_phnum):
        o = e_phoff + i * e_phentsize
        if o + 56 > len(raw):
            break
        p_type, p_flags = struct.unpack_from("<II", raw, o)
        p_off, p_va, p_pa, p_filesz, p_memsz, p_align = struct.unpack_from(
            "<QQQQQQ", raw, o + 8
        )
        if p_type == 1 and p_filesz and p_off < len(raw):
            segs.append(
                {
                    "off": p_off,
                    "vaddr": p_va,
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                    "flags": p_flags,
                }
            )
    return {
        "machine": e_machine,
        "machine_name": {0xB7: "AArch64", 0x28: "ARM", 0x3E: "x86-64"}.get(
            e_machine, "unknown(0x%x)" % e_machine
        ),
        "entry": e_entry,
        "segments": segs,
    }


def _plausible_dict_size(d: int) -> bool:
    if not (0x1000 <= d <= 0x20000000):
        return False
    return (d & (d - 1)) == 0 or (d % 3 == 0 and ((d // 3) & (d // 3 - 1)) == 0)


def _timed_decompress(data: bytes, fmt: int):
    try:
        return lzma.decompress(data, format=fmt)
    except (lzma.LZMAError, EOFError, ValueError):
        return None


def _unwrap(raw: bytes, depth: int, notes: list):
    """剥离外层容器：ELF / Android boot / XZ / 裸 LZMA / gzip。返回 Image 或 None。"""
    if depth > 3:
        return None
    if _elf_ok(raw):
        notes.append("检测到 ELF 头")
        try:
            elf = parse_elf(raw)
        except ValueError as e:
            notes.append("ELF 解析失败：%s，改按裸二进制处理" % e)
            elf = None
        if elf is None:
            pass
        else:
            notes.append(
                "ELF: %s, %d 个 PT_LOAD, entry=0x%x"
                % (elf["machine_name"], len(elf["segments"]), elf["entry"])
            )
            return Image(raw, "elf", notes, elf)

    if raw[:8] == b"ANDROID!":
        notes.append("检测到 Android boot image 头")
        if len(raw) >= 44:
            kernel_size = struct.unpack_from("<I", raw, 8)[0]
            page = struct.unpack_from("<I", raw, 36)[0] or 2048
            koff = page
            if 0 < kernel_size <= len(raw) - koff:
                notes.append(
                    "从中提取 kernel（%d 字节，page=%d）继续分析" % (kernel_size, page)
                )
                sub = _unwrap(raw[koff : koff + kernel_size], depth + 1, notes)
                if sub is not None:
                    sub.notes.insert(0, "外层为 Android boot image")
                    return sub
        notes.append("boot image 里的 kernel 无法继续解包")

    if raw[:6] == b"\xfd7zXZ\x00":
        out = _timed_decompress(raw, lzma.FORMAT_XZ)
        if out:
            notes.append("已解压 XZ 容器（%d → %d 字节）" % (len(raw), len(out)))
            sub = _unwrap(out, depth + 1, notes)
            if sub is not None:
                return sub
        notes.append("XZ 解压失败")

    # 裸 LZMA：正确做法是 0x5D + 4 字节字典大小，而不是帖子里找的 5d 00 00 00
    tried = 0
    off = -1
    while True:
        off = raw.find(b"\x5d", off + 1)
        if off < 0 or tried >= 8:
            break
        if off + 5 > len(raw):
            break
        dict_size = struct.unpack_from("<I", raw, off + 1)[0]
        if not _plausible_dict_size(dict_size):
            continue
        tried += 1
        out = _timed_decompress(raw[off:], lzma.FORMAT_ALONE)
        if out and len(out) > 0x1000:
            notes.append(
                "在偏移 0x%x 处找到裸 LZMA 流（字典 0x%x），解压 %d → %d 字节"
                % (off, dict_size, len(raw) - off, len(out))
            )
            sub = _unwrap(out, depth + 1, notes)
            if sub is not None:
                return sub
    if tried:
        notes.append("试了 %d 个 LZMA 候选头，均解压失败" % tried)

    if raw[:2] == b"\x1f\x8b":
        try:
            out = gzip.decompress(raw)
        except OSError:
            out = None
        if out:
            notes.append("已解压 gzip（%d → %d 字节）" % (len(raw), len(out)))
            return _unwrap(out, depth + 1, notes)
        notes.append("gzip 解压失败")

    # 走到这里：既不是 ELF 也不是已知容器。按裸二进制处理（偏移即地址）。
    notes.append("（本层）未识别出容器格式，按裸二进制分析")
    return Image(raw, "raw", notes)


def load_image(path: str) -> Image:
    size = os.path.getsize(path)
    if size > MAX_IMAGE:
        raise SystemExit("文件过大（%d 字节），拒绝加载" % size)
    with open(path, "rb") as f:
        raw = f.read()
    notes: list = []
    img = _unwrap(raw, 0, notes)
    if img is None:
        # 既不是 ELF 也不是已知容器：当作裸代码段分析
        img = Image(raw, "raw", notes + ["未识别出容器格式，按裸二进制（偏移=地址）分析"])
    img.path = path
    return img


# --------------------------------------------------------------------------
# AArch64 指令解码（只覆盖本工具需要的子集；其他一律打印 .word）
# --------------------------------------------------------------------------
MASK = 0xFFFFFFFF


def dec_adrp(w: int, pc: int):
    if (w & 0x9F000000) != 0x90000000:
        return None
    rd = w & 0x1F
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return rd, ((pc & ~0xFFF) + (imm << 12)) & 0xFFFFFFFFFFFFFFFF


def dec_add_imm(w: int, pc: int, is64: bool = True):
    mask = 0xFF800000
    base = 0x91000000 if is64 else 0x11000000
    if (w & mask) != base:
        return None
    sh = (w >> 22) & 3
    if sh > 1:
        return None
    imm12 = (w >> 10) & 0xFFF
    rn = (w >> 5) & 0x1F
    rd = w & 0x1F
    return {"rd": rd, "rn": rn, "imm12": imm12, "sh": sh}


def dec_ldrb_imm(w: int):
    if (w & 0xFFC00000) != 0x39400000:
        return None
    imm12 = (w >> 10) & 0xFFF
    rn = (w >> 5) & 0x1F
    rt = w & 0x1F
    return {"rt": rt, "rn": rn, "imm": imm12}


def dec_ldr_imm(w: int):
    """LDR (immediate, unsigned offset) 32/64 位。"""
    if (w & 0xFFC00000) == 0xB9400000:
        size, width = 4, "w"
    elif (w & 0xFFC00000) == 0xF9400000:
        size, width = 8, "x"
    else:
        return None
    imm = ((w >> 10) & 0xFFF) * size
    rn = (w >> 5) & 0x1F
    rt = w & 0x1F
    return {"rt": rt, "rn": rn, "imm": imm, "width": width}


def dec_ldur_imm(w: int):
    """LDUR / LDURB（unscaled，imm9 带符号）。负偏移的 ldr 一定落在这里。"""
    if (w & 0xFFE00C00) == 0xB8400000:  # load, unscaled, GPR
        size = (w >> 30) & 3
        opc = (w >> 22) & 3
        if opc != 1:  # 只看普通 load（不是 load signed）
            return None
        imm9 = (w >> 12) & 0x1FF
        if imm9 & 0x100:
            imm9 -= 0x200
        rn = (w >> 5) & 0x1F
        rt = w & 0x1F
        width = {0: "b", 1: "h", 2: "w", 3: "x"}[size]
        return {"rt": rt, "rn": rn, "imm": imm9, "width": width, "signed": True}
    return None


def dec_ldur_byte(w: int):
    if (w & 0xFFE00C00) == 0x38400000:  # LDURB
        imm9 = (w >> 12) & 0x1FF
        if imm9 & 0x100:
            imm9 -= 0x200
        return {"rt": w & 0x1F, "rn": (w >> 5) & 0x1F, "imm": imm9}
    return None


def dec_movz(w: int, is64: bool = True):
    base = 0xD2800000 if is64 else 0x52800000
    if (w & (0xFF800000 if is64 else 0x7F800000)) != base:
        return None
    hw = (w >> 21) & 3
    imm = ((w >> 5) & 0xFFFF) << (16 * hw)
    return {"rd": w & 0x1F, "imm": imm, "hw": hw}


def dec_movk(w: int, is64: bool = True):
    base = 0xF2800000 if is64 else 0x72800000
    if (w & (0xFF800000 if is64 else 0x7F800000)) != base:
        return None
    hw = (w >> 21) & 3
    return {"rd": w & 0x1F, "imm": (w >> 5) & 0xFFFF, "hw": hw}


def dec_strb_imm(w: int):
    if (w & 0xFFC00000) != 0x39000000:
        return None
    return {"rt": w & 0x1F, "rn": (w >> 5) & 0x1F, "imm": (w >> 10) & 0xFFF}


def dec_br(w: int):
    if (w & 0xFFFFFC1F) == 0xD61F0000:
        return {"rn": (w >> 5) & 0x1F}
    return None


def dec_is_ret(w: int) -> bool:
    return w == 0xD65F03C0


def disasm_one(w: int, pc: int) -> str:
    d = dec_adrp(w, pc)
    if d:
        return "adrp x%d, 0x%x" % (d[0], d[1])
    d = dec_add_imm(w, pc, True)
    if d:
        return "add x%d, x%d, #0x%x" % (d["rd"], d["rn"], d["imm12"] << (12 if d["sh"] else 0))
    d = dec_add_imm(w, pc, False)
    if d:
        return "add w%d, w%d, #0x%x" % (d["rd"], d["rn"], d["imm12"] << (12 if d["sh"] else 0))
    d = dec_ldrb_imm(w)
    if d:
        return "ldrb w%d, [x%d, #0x%x]" % (d["rt"], d["rn"], d["imm"])
    d = dec_ldr_imm(w)
    if d:
        return "ldr %s%d, [x%d, #0x%x]" % (d["width"], d["rt"], d["rn"], d["imm"])
    d = dec_ldur_imm(w)
    if d:
        return "ldur %s%d, [x%d, %s]" % (
            d["width"],
            d["rt"],
            d["rn"],
            ("#-0x%x" % -d["imm"]) if d["imm"] < 0 else ("#0x%x" % d["imm"]),
        )
    d = dec_ldur_byte(w)
    if d:
        return "ldurb w%d, [x%d, %s]" % (
            d["rt"],
            d["rn"],
            ("#-0x%x" % -d["imm"]) if d["imm"] < 0 else ("#0x%x" % d["imm"]),
        )
    d = dec_movz(w, True)
    if d:
        return "movz x%d, #0x%x" % (d["rd"], d["imm"])
    d = dec_movz(w, False)
    if d:
        return "movz w%d, #0x%x" % (d["rd"], d["imm"])
    d = dec_movk(w, True)
    if d:
        return "movk x%d, #0x%x, lsl #%d" % (d["rd"], d["imm"], 16 * d["hw"])
    d = dec_strb_imm(w)
    if d:
        return "strb w%d, [x%d, #0x%x]" % (d["rt"], d["rn"], d["imm"])
    d = dec_br(w)
    if d:
        return "br x%d" % d["rn"]
    if dec_is_ret(w):
        return "ret"
    if w == 0xD503201F:
        return "nop"
    return ".word 0x%08x" % w


def u32(raw: bytes, off: int) -> int:
    return struct.unpack_from("<I", raw, off)[0]


# --------------------------------------------------------------------------
# 扫描
# --------------------------------------------------------------------------
def exec_regions(img: Image):
    ex = [r for r in img.regions if r.get("exec", True)]
    return ex or img.regions


def iter_words(img: Image):
    for r in exec_regions(img):
        n = r["size"] // 4
        for i in range(n):
            yield r["va"] + i * 4, u32(img.raw, r["off"] + i * 4)


def words_back(img: Image, va: int, count: int):
    """取 va 之前 count 条指令（同一段内），按从旧到新返回。"""
    out = []
    for k in range(count, 0, -1):
        a = va - k * 4
        o = img.va_to_off(a)
        if o is None:
            out.append(None)
        else:
            out.append((a, u32(img.raw, o)))
    return [x for x in out if x]


def trace_pointer_base(img: Image, va: int, reg: int, look_back: int = 8):
    """往回找 adrp xN / add xN, xN, #imm，还原寄存器基址。"""
    base = None
    for a, w in words_back(img, va, look_back):
        d = dec_adrp(w, a)
        if d and d[0] == reg:
            base = d[1]
            continue
        add = dec_add_imm(w, a, True)
        if add and add["rd"] == reg and add["rn"] == reg and base is not None:
            base = (base + (add["imm12"] << (12 if add["sh"] else 0))) & 0xFFFFFFFFFFFFFFFF
    return base


def find_strings(img: Image, needles) -> list:
    hits = []
    seen = set()
    for r in img.regions:
        blob = img.raw[r["off"] : r["off"] + r["size"]]
        for nd in needles:
            start = 0
            while True:
                i = blob.find(nd, start)
                if i < 0:
                    break
                start = i + 1
                va = r["va"] + i
                if va in seen:
                    continue
                seen.add(va)
                end = blob.find(b"\x00", i)
                text = blob[i : end if end > 0 else i + len(nd)]
                hits.append(
                    {"va": va, "text": text.decode("ascii", "replace"), "needle": nd.decode()}
                )
    hits.sort(key=lambda h: h["va"])
    return hits


def scan_string_xrefs(img: Image, strings: list, window: int = 0x40) -> list:
    """找 adrp+add 组合，目标落在字符串附近 —— 用来定位处理函数。"""
    ranges = [(s["va"], s["va"] + window, s) for s in strings]
    out = []
    seen = set()
    for va, w in iter_words(img):
        d = dec_adrp(w, va)
        if not d:
            continue
        rd, page = d
        nxt = img.va_to_off(va + 4)
        if nxt is None:
            continue
        w2 = u32(img.raw, nxt)
        add = dec_add_imm(w2, va + 4, True)
        if not add or add["rn"] != rd:
            continue
        target = (page + (add["imm12"] << (12 if add["sh"] else 0))) & 0xFFFFFFFFFFFFFFFF
        add_rd = add["rd"]
        if (va, target) in seen:
            continue
        for lo, hi, s in ranges:
            if lo <= target < hi:
                seen.add((va, target))
                out.append(
                    {
                        "code_va": va,
                        "target_va": target,
                        "string_va": s["va"],
                        "string": s["text"],
                        "insns": [
                            disasm_one(w, va),
                            disasm_one(w2, va + 4),
                        ],
                        "base_reg": "x%d" % add_rd,
                    }
                )
                break
    out.sort(key=lambda x: x["code_va"])
    return out


def scan_flag_reads(img: Image) -> list:
    """所有 ldrb 读取（含可还原基址的），重点标注偏移 0xd / 0x8d。"""
    out = []
    for va, w in iter_words(img):
        d = dec_ldrb_imm(w)
        if not d:
            continue
        base = trace_pointer_base(img, va, d["rn"], look_back=8)
        target = None
        if base is not None:
            target = (base + d["imm"]) & 0xFFFFFFFFFFFFFFFF
        out.append(
            {
                "read_va": va,
                "reg": "x%d" % d["rn"],
                "imm": d["imm"],
                "base": base,
                "target_va": target,
                "disasm": disasm_one(w, va),
                "interesting": d["imm"] in (0xD, 0x8D),
            }
        )
    return out


def scan_overflow_sig(img: Image) -> dict | None:
    """帖子里指认的 08 c3 5e b8 / 00 11 00 11。"""
    pat = b"\x08\xc3\x5e\xb8\x00\x11\x00\x11"
    for r in img.regions:
        blob = img.raw[r["off"] : r["off"] + r["size"]]
        i = blob.find(pat)
        if i < 0:
            continue
        off = r["off"] + i
        va = r["va"] + i
        w1, w2 = u32(img.raw, off), u32(img.raw, off + 4)
        actual1, actual2 = disasm_one(w1, va), disasm_one(w2, va + 4)
        claimed1 = "ldr w8, [x24, #-0x14]"
        claimed2 = "add w0, w8, #4"
        first = dec_ldur_imm(w1) or dec_ldr_imm(w1)
        second = dec_add_imm(w2, va + 4, False)
        sem = {"rt": None, "rn": None, "imm": None, "same_regs": False, "imm_delta": None}
        if first:
            sem["rt"] = first["rt"]
            sem["rn"] = first["rn"]
            sem["imm"] = first["imm"]
            sem["same_regs"] = first["rt"] == 8 and first["rn"] == 24
            if first["imm"] is not None:
                sem["imm_delta"] = first["imm"] - (-0x14)
        sem["second_ok"] = bool(
            second and second["rd"] == 0 and second["rn"] == 8 and second["imm12"] == 4 and second["sh"] == 0
        )
        sem["semantic_ok"] = bool(sem["same_regs"] and sem["imm_delta"] == 0 and sem["second_ok"])
        return {
            "va": va,
            "file_off": off,
            "words": ["0x%08x" % w1, "0x%08x" % w2],
            "claimed": [claimed1, claimed2],
            "actual": [actual1, actual2],
            "match_first": actual1 == claimed1,
            "match_second": actual2 == claimed2,
            "semantic": sem,
            "context_after": [
                disasm_one(u32(img.raw, off + 8 + k * 4), va + 8 + k * 4)
                for k in range(4)
                if off + 8 + k * 4 + 4 <= len(img.raw)
            ],
        }
    return None


# --------------------------------------------------------------------------
# 结论
# --------------------------------------------------------------------------
def build_report(img: Image, base: int | None, verbose: bool) -> dict:
    raw = img.raw
    report = {
        "file": getattr(img, "path", "<demo>"),
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "format": img.fmt,
        "notes": img.notes,
        "elf": img.elf,
        "base": base,
        "regions": [dict(r) for r in img.regions],
        "strings": [],
        "string_xrefs": [],
        "flag_reads": [],
        "overflow_sig": None,
        "claimed_addresses": [],
        "verdicts": [],
    }

    strings = find_strings(img, [b"oem unlock", b"unlock", b"Unlock", b"UNLOCK"])
    report["strings"] = strings
    report["string_xrefs"] = scan_string_xrefs(img, strings)
    report["flag_reads"] = scan_flag_reads(img)
    sig = scan_overflow_sig(img)
    report["overflow_sig"] = sig

    for addr, why in CLAIMED_ADDRS.items():
        report["claimed_addresses"].append(
            {
                "addr": addr,
                "why": why,
                "in_image": img.contains(addr),
            }
        )

    # --- 逐条判定 ------------------------------------------------------
    v = report["verdicts"]

    def add(claim, status, detail):
        v.append({"claim": claim, "status": status, "detail": detail})

    add(
        "传输层：把 b'FASTBOOT' + b'FFFFFFFF' 当成长度头",
        "与协议事实不符",
        "Android fastboot 的包格式是 [4 字节大端长度][ASCII 命令]，没有 FASTBOOT 魔术头；"
        "设备会把 'FAST' 读成长度 0x46415354（约 1.18 GB）。这个包到不了 oem unlock 的处理逻辑。"
        "（本工具不发送任何数据，此条为协议层面的静态判断。）",
    )

    if sig is None:
        add(
            "溢出点：镜像内找 08 c3 5e b8 + 00 11 00 11",
            "未发现",
            "该字节序列在镜像中不存在。要么版本不同，要么这个「特征码」本身是编造的。",
        )
    else:
        sem = sig.get("semantic", {})
        same_regs = sem.get("same_regs")
        delta = sem.get("imm_delta")
        if sem.get("semantic_ok"):
            status = "发现序列，语义与帖子描述一致"
            detail = (
                "实际解码：%s；%s。与帖子的 %s；%s 等价（负偏移在 AArch64 上用 unscaled 编码，"
                "反汇编器一般也印成 ldr）。注意：这只说明镜像里有这两条指令，"
                "不能说明长度确实没校验，更不能说明能拿到控制流。"
                % (sig["actual"][0], sig["actual"][1], sig["claimed"][0], sig["claimed"][1])
            )
        elif same_regs:
            status = "发现序列，寄存器一致但偏移不符"
            detail = (
                "实际解码：%s；%s。帖子声称：%s；%s。"
                "目标寄存器与基址寄存器都对得上，但偏移是 %s 而不是 -0x14（差 0x%x）。"
                % (
                    sig["actual"][0],
                    sig["actual"][1],
                    sig["claimed"][0],
                    sig["claimed"][1],
                    ("%d" % sem["imm"]) if sem.get("imm") is not None else "未知",
                    abs(delta) if delta is not None else 0,
                )
            )
        else:
            status = "发现序列，但解码与帖子描述不符"
            detail = (
                "实际解码：%s；%s。帖子声称：%s；%s。"
                "这两条机器码对应的并不是帖子里写的指令。"
                % (sig["actual"][0], sig["actual"][1], sig["claimed"][0], sig["claimed"][1])
            )
        add("溢出点：镜像内找 08 c3 5e b8 + 00 11 00 11", status, detail)

    if img.contains(0x40000000):
        add(
            "Shellcode 落点 0x40000000",
            "地址落在镜像内",
            "需要进一步确认该处是否可写、是否真是缓冲区；静态无法判定。",
        )
    else:
        add(
            "Shellcode 落点 0x40000000",
            "该地址不在任何 PT_LOAD / 镜像区间内",
            "被跳转过去的 shellcode 不会出现在这个地址；载荷实际落在接收缓冲区里，地址是运行时才确定的。",
        )

    for item in report["claimed_addresses"]:
        if item["addr"] == 0x40000000:
            continue
        add(
            "解锁标志位地址 0x%x" % item["addr"],
            "在镜像内" if item["in_image"] else "不在镜像映射范围内",
            item["why"]
            + ("；可作为候选继续人工核对。" if item["in_image"] else "；静态地址对不上，说明是从别处抄来的。"),
        )

    interesting = [f for f in report["flag_reads"] if f["interesting"] and f["target_va"]]
    if interesting:
        add(
            "标志位读取点 ldrb（偏移 0xd / 0x8d）",
            "发现 %d 处可还原地址" % len(interesting),
            "候选目标地址："
            + "，".join("0x%x（来自 %s）" % (f["target_va"], f["disasm"]) for f in interesting[:6]),
        )
    else:
        add(
            "标志位读取点 ldrb（偏移 0xd / 0x8d）",
            "未发现可还原地址的实例",
            "没有找到前面带 adrp/add 的 ldrb [#0xd] 读取；若镜像为裸二进制且未给 --base，地址无法还原属正常。",
        )

    if report["string_xrefs"]:
        add(
            "定位 'oem unlock'/'unlock' 字符串引用",
            "命中 %d 处" % len(report["string_xrefs"]),
            "可从这些代码点向上找函数入口，人工核对是否真的缺少长度校验。",
        )
    else:
        add(
            "定位 'oem unlock'/'unlock' 字符串引用",
            "未命中",
            "镜像里没有找到引用这些字符串的 adrp+add；说明该镜像可能不含 fastboot 命令解析，或字符串被压缩/加密。",
        )

    if verbose:
        report["all_flag_reads"] = report["flag_reads"]
    return report


def render(report: dict, verbose: bool = False) -> str:
    L = []
    a = L.append
    a("=" * 72)
    a("ABL 镜像静态核查报告")
    a("=" * 72)
    a("文件      : %s" % report["file"])
    a("大小      : %d 字节" % report["size"])
    a("SHA-256   : %s" % report["sha256"])
    a("容器格式  : %s" % report["format"])
    if report.get("base") is not None:
        a("加载基址  : 0x%x（由 --base 指定）" % report["base"])
    for n in report["notes"]:
        a("  · %s" % n)
    if report["elf"]:
        e = report["elf"]
        a("机器类型  : %s" % e["machine_name"])
        a("入口地址  : 0x%x" % e["entry"])
        for r in report["regions"]:
            a("  段 %-14s off=0x%-8x va=0x%-10x size=0x%x" % (r["name"], r["off"], r["va"], r["size"]))
    else:
        a("地址映射  : 偏移即地址（裸二进制）")

    a("")
    a("-" * 72)
    a("一、结论")
    a("-" * 72)
    if str(report.get("file", "")).startswith("<demo"):
        a("（以下判定基于内置合成样本，只用于演示报告格式，不代表任何真实镜像）")
        a("")
    for i, v in enumerate(report["verdicts"], 1):
        mark = {
            "与协议事实不符": "✗",
            "未发现": "✗",
            "未命中": "✗",
            "不在镜像映射范围内": "✗",
            "该地址不在任何 PT_LOAD / 镜像区间内": "✗",
            "发现序列，寄存器一致但偏移不符": "⚠",
            "发现序列，但解码与帖子描述不符": "⚠",
            "发现序列，语义与帖子描述一致": "✓",
        }.get(v["status"], "✓")
        a("[%s] %d. %s" % (mark, i, v["claim"]))
        a("      → %s" % v["status"])
        for line in textwrap.wrap(v["detail"], 62):
            a("        %s" % line)

    a("")
    a("-" * 72)
    a("二、证据")
    a("-" * 72)
    if report["overflow_sig"]:
        s = report["overflow_sig"]
        a("溢出特征码 @ va=0x%x (file 0x%x)" % (s["va"], s["file_off"]))
        a("  机器码   : %s" % "  ".join(s["words"]))
        a("  反汇编   : %s ; %s" % (s["actual"][0], s["actual"][1]))
        a("  帖子声称 : %s ; %s" % (s["claimed"][0], s["claimed"][1]))
        a("  后续指令 : %s" % " ; ".join(s["context_after"]))
    else:
        a("溢出特征码 : 未找到")

    a("")
    a("字符串     : %d 处（oem unlock / unlock）" % len(report["strings"]))
    for s in report["strings"][:8]:
        a("  0x%-10x %r" % (s["va"], s["text"]))
    if len(report["strings"]) > 8:
        a("  ... 共 %d 处" % len(report["strings"]))

    a("")
    a("字符串引用 : %d 处" % len(report["string_xrefs"]))
    for x in report["string_xrefs"][:12]:
        a("  code 0x%-10x → 0x%-10x %r" % (x["code_va"], x["target_va"], x["string"]))
        a("      %s" % " ; ".join(x["insns"]))

    reads = report.get("all_flag_reads") if verbose else [
        f for f in report["flag_reads"] if f["interesting"] or f["target_va"]
    ]
    a("")
    a("ldrb 读取点 : %d 处%s" % (len(reads), "（-v 显示全部）" if verbose else ""))
    for f in reads[:20]:
        tgt = "0x%x" % f["target_va"] if f["target_va"] else "地址不可还原"
        a("  0x%-10x %-28s → %s%s" % (f["read_va"], f["disasm"], tgt, "  ← 偏移吻合" if f["interesting"] else ""))

    a("")
    a("传说地址是否在镜像内：")
    for item in report["claimed_addresses"]:
        a("  0x%-10x %s" % (item["addr"], "在" if item["in_image"] else "不在"))

    a("")
    a("-" * 72)
    a("三、说明")
    a("-" * 72)
    a("· 本工具只读文件，不连接设备、不发送 USB 数据、不写分区。")
    a("· 静态分析能证伪，不能证实“可利用”：找到指令只说明镜像里有这几条指令，")
    a("  不能说明长度确实没校验、不能说明缓存区大小、更不能说明能拿到控制流。")
    a("· 要证明可利用，需要真实镜像 + 调用链核对 + 有设备可回滚的实测。")
    return "\n".join(L)


# --------------------------------------------------------------------------
# 合成样本（用于 --demo 与自测；不含任何真实设备数据）
# --------------------------------------------------------------------------
def _adrp(rd: int, pc: int, target: int) -> int:
    delta = (target - (pc & ~0xFFF)) >> 12
    imm = delta & 0x1FFFFF
    immlo = imm & 3
    immhi = (imm >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | rd


def _add(rn: int, rd: int, imm: int) -> int:
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd


def _ldrb(rt: int, rn: int, imm: int) -> int:
    return 0x39400000 | ((imm & 0xFFF) << 10) | (rn << 5) | rt


def demo_bytes() -> bytes:
    """构造一份最小样本：带 adrp/add/ldrb 的“标志位读取”、unlock 字符串引用、
    以及帖子里那段 08 c3 5e b8 / 00 11 00 11。

    所有目标都用 PC 相对方式编码，因此同一份字节在 base=0 的裸模式和
    base=0x40001000 的 ELF 模式下都能得到一致结果。
    """
    size = 0x2100
    buf = bytearray(size)

    def put(off, words):
        for i, w in enumerate(words):
            struct.pack_into("<I", buf, off + i * 4, w & MASK)

    # 0x1000: adrp x8, page(0x1800) ; add x8, x8, #0x800 ; ldrb w0, [x8, #0xd] ; ret
    put(0x1000, [_adrp(8, 0x1000, 0x1800), _add(8, 8, 0x800), _ldrb(0, 8, 0xD), 0xD65F03C0])
    # 0x1010: adrp x1, page(0x1800) ; add x1, x1, #0 ; ret  （字符串引用）
    put(0x1010, [_adrp(1, 0x1010, 0x1800), _add(1, 1, 0x800), 0xD65F03C0])
    # 0x1020: 帖子里的“溢出点”
    put(0x1020, [0xB85EC308, 0x11001100, 0xD65F03C0])
    # 0x1800: 字符串
    buf[0x1800:0x180B] = b"oem unlock\x00"
    # 0x1810: 另一处 unlock
    buf[0x1810:0x1817] = b"unlock\x00"
    # 0x2000: movz/movk/movz/strb/ret（帖子里那种 shellcode）
    put(0x2000, [0xD29B9FA0, 0xF2A01320, 0x52800001, 0x39000001, 0xD65F03C0])
    return bytes(buf)


def demo_elf() -> bytes:
    """把 demo_bytes() 包成一个最小 ELF64。

    布局：文件偏移 0 → VA 0x9fc00000（单段 PT_LOAD，模仿真实 ABL 的加载地址），
    于是 demo_bytes() 里 0x1000 处的指令 → VA 0x9fc01000，
    0x1800 处的字符串 → VA 0x9fc01800，0x180d 的读取点 → 0x9fc0180d。
    demo_bytes() 前 0x78 字节全是 0，正好被 ELF 头/程序头覆盖。
    """
    code = bytearray(demo_bytes())
    phoff = 64
    phentsize = 56
    total = len(code)
    base = 0x9FC00000

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2  # 64 位
    ehdr[5] = 1  # 小端
    ehdr[6] = 1
    struct.pack_into("<H", ehdr, 16, 2)  # ET_EXEC
    struct.pack_into("<H", ehdr, 18, 0xB7)  # AArch64
    struct.pack_into("<I", ehdr, 20, 1)
    struct.pack_into("<Q", ehdr, 24, base + 0x1000)  # entry
    struct.pack_into("<Q", ehdr, 32, phoff)
    struct.pack_into("<H", ehdr, 52, 64)
    struct.pack_into("<H", ehdr, 54, phentsize)
    struct.pack_into("<H", ehdr, 56, 1)

    ph = bytearray(phentsize)
    struct.pack_into("<I", ph, 0, 1)  # PT_LOAD
    struct.pack_into("<I", ph, 4, 5)  # R|X
    struct.pack_into("<Q", ph, 8, 0)  # p_offset
    struct.pack_into("<Q", ph, 16, base)  # p_vaddr
    struct.pack_into("<Q", ph, 24, base)  # p_paddr
    struct.pack_into("<Q", ph, 32, total)  # p_filesz
    struct.pack_into("<Q", ph, 40, total)  # p_memsz
    struct.pack_into("<Q", ph, 48, 0x1000)

    out = bytearray(code)
    out[0:64] = ehdr
    out[64 : 64 + phentsize] = ph
    return bytes(out)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="ABL 镜像静态核查（只读，不连接设备）")
    ap.add_argument("image", nargs="?", help="abl 镜像路径（raw / ELF / LZMA / XZ / boot.img）")
    ap.add_argument("--base", type=lambda s: int(s, 0), default=None, help="裸二进制加载基址，如 0x9fc00000")
    ap.add_argument("--json", metavar="PATH", help="把完整结果写成 JSON")
    ap.add_argument("--demo", nargs="?", const="raw", choices=["raw", "elf"], help="用内置合成样本运行")
    ap.add_argument("-v", "--verbose", action="store_true", help="输出全部候选，不只关注的")
    args = ap.parse_args(argv)

    if args.demo:
        raw = demo_elf() if args.demo == "elf" else demo_bytes()
        notes: list = []
        img = _unwrap(raw, 0, notes)
        if img is None:
            img = Image(raw, "raw", notes)
        else:
            img.notes = notes
        img.path = "<demo:%s>" % args.demo
        img.notes.insert(0, "★ 演示模式：内置合成样本，不是真实设备镜像 ★")
    else:
        if not args.image:
            ap.error("需要镜像路径，或用 --demo")
        if not os.path.isfile(args.image):
            print("[-] 文件不存在: %s" % args.image, file=sys.stderr)
            return 2
        try:
            img = load_image(args.image)
        except SystemExit as e:
            print("[-] %s" % e, file=sys.stderr)
            return 2
        if args.base is not None:
            if img.fmt == "elf":
                print("[!] 已是 ELF，忽略 --base（地址来自程序头）", file=sys.stderr)
            else:
                img = img.rebase(args.base)

    report = build_report(img, args.base, args.verbose)
    if not report["verdicts"]:
        report["verdicts"] = []
    print(render(report, args.verbose))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print("\n[+] JSON 已写入 %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
