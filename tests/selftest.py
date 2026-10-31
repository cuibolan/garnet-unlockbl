#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""analyze_abl.py 的自测。只依赖标准库，不需要真实设备镜像。

运行：
    python tests/selftest.py
"""

import json
import lzma
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOOL = os.path.join(ROOT, "analyze_abl.py")
sys.path.insert(0, ROOT)

import analyze_abl as A  # noqa: E402

FAILS = []


def check(name, cond, detail=""):
    if cond:
        print("  PASS  %s" % name)
    else:
        print("  FAIL  %s  %s" % (name, detail))
        FAILS.append(name)


def run(args):
    """在进程内调用 main()，不依赖 subprocess。

    受限环境（例如 DSH 沙箱）禁止子进程创建管道，subprocess 抓 stdout 会直接抛
    PermissionError；进程内调用更稳，也更快。
    """
    import io
    from types import SimpleNamespace

    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        code = A.main(args)
    finally:
        sys.stdout = old
    return SimpleNamespace(returncode=code, stdout=buf.getvalue(), stderr="")


def run_json(img_path, extra=None):
    out = img_path + ".report.json"
    try:
        p = run([img_path, "--json", out] + (extra or []))
        if p.returncode != 0:
            raise SystemExit("工具退出码 %d:\n%s\n%s" % (p.returncode, p.stdout, p.stderr))
        with open(out, encoding="utf-8") as fh:
            return json.load(fh), p.stdout
    finally:
        if os.path.exists(out):
            os.unlink(out)


def test_raw(tmp):
    print("[1] 裸二进制模式")
    path = os.path.join(tmp, "_selftest_raw.bin")
    with open(path, "wb") as f:
        f.write(A.demo_bytes())
    rep, text = run_json(path)

    reads = [r for r in rep["flag_reads"] if r["interesting"]]
    check("找到 ldrb 偏移 0xd 读取点", len(reads) == 1, "实际 %d 处" % len(reads))
    check("目标地址 = 0x180d", reads and reads[0]["target_va"] == 0x180D, str(reads[:1]))
    check("字符串引用命中", len(rep["string_xrefs"]) >= 1, str(rep["string_xrefs"]))
    check(
        "字符串引用目标 = 0x1800",
        any(x["target_va"] == 0x1800 for x in rep["string_xrefs"]),
        str([x["target_va"] for x in rep["string_xrefs"]]),
    )
    sig = rep["overflow_sig"]
    check("溢出特征码被找到", sig is not None)
    check("语义与帖子一致(ldur 等价 ldr)", sig and sig["semantic"]["semantic_ok"], str(sig and sig["semantic"]))
    check("实际解码为 ldur w8,[x24,#-0x14]", sig and sig["actual"][0] == "ldur w8, [x24, #-0x14]", sig and sig["actual"][0])
    check("传说地址均不在镜像内", all(not c["in_image"] for c in rep["claimed_addresses"]))
    check("报告里出现结论段落", "结论" in text)


def test_elf(tmp):
    print("[2] ELF 模式（VA 映射）")
    path = os.path.join(tmp, "_selftest.elf")
    with open(path, "wb") as f:
        f.write(A.demo_elf())
    rep, text = run_json(path)

    check("识别为 ELF", rep["format"] == "elf", str(rep.get("format")))
    check("机器类型 AArch64", rep["elf"] and rep["elf"]["machine_name"] == "AArch64")
    reads = [r for r in rep["flag_reads"] if r["interesting"]]
    check("ELF 下目标地址 = 0x9fc0180d", reads and reads[0]["target_va"] == 0x9FC0180D, str(reads[:1]))
    check(
        "ELF 下字符串引用 = 0x9fc01800",
        any(x["target_va"] == 0x9FC01800 for x in rep["string_xrefs"]),
        str([x["target_va"] for x in rep["string_xrefs"]]),
    )
    check("0x40000000 不在镜像内", not any(c["in_image"] for c in rep["claimed_addresses"] if c["addr"] == 0x40000000))


def test_lzma(tmp):
    print("[3] 裸 LZMA 容器")
    path = os.path.join(tmp, "_selftest.lzma")
    payload = lzma.compress(A.demo_bytes(), format=lzma.FORMAT_ALONE)
    with open(path, "wb") as f:
        f.write(payload)
    rep, text = run_json(path)
    joined = " ".join(rep["notes"])
    check("解压出 LZMA 容器", "LZMA" in joined, joined[:120])
    reads = [r for r in rep["flag_reads"] if r["interesting"]]
    check("解压后仍能定位 0x180d", reads and reads[0]["target_va"] == 0x180D, str(reads[:1]))


def test_xz(tmp):
    print("[4] XZ 容器")
    path = os.path.join(tmp, "_selftest.xz")
    with open(path, "wb") as f:
        f.write(lzma.compress(A.demo_bytes(), format=lzma.FORMAT_XZ))
    rep, text = run_json(path)
    check("识别 XZ", any("XZ" in n for n in rep["notes"]), " ".join(rep["notes"])[:120])


def test_cli_errors(tmp):
    print("[5] 命令行行为")
    p = run(["--demo"])
    check("--demo 退出码 0", p.returncode == 0, p.stderr[:200])
    check("--demo 有演示横幅", "演示" in p.stdout)
    p = run(["Z:/definitely/not/here.img"])
    check("不存在的文件返回 2", p.returncode == 2, str(p.returncode))
    p = run(["--demo", "elf", "-v"])
    check("--demo elf -v 退出码 0", p.returncode == 0, p.stderr[:200])


def test_instr_decoders():
    print("[6] 指令解码器")
    check("adrp x8 解码", A.dec_adrp(0x90000008, 0x1000) == (8, 0x1000), str(A.dec_adrp(0x90000008, 0x1000)))
    check("ldrb w0,[x8,#0xd] 字节码", A.disasm_one(0x39403500, 0) == "ldrb w0, [x8, #0xd]", A.disasm_one(0x39403500, 0))
    check("08 c3 5e b8 = ldur w8,[x24,#-0x14]", A.disasm_one(0xB85EC308, 0) == "ldur w8, [x24, #-0x14]", A.disasm_one(0xB85EC308, 0))
    check("00 11 00 11 = add w0, w8, #4", A.disasm_one(0x11001100, 0).startswith("add w0, w8, #"), A.disasm_one(0x11001100, 0))


def main():
    print("analyze_abl.py 自测")
    print("=" * 60)
    test_instr_decoders()
    # 注意：不使用 tempfile.mkdtemp —— 某些受限环境（含 DSH 沙箱）只允许写
    # 已存在的目录，新建子目录可能没有写权限。这里直接在仓库根目录放临时文件。
    test_raw(ROOT)
    test_elf(ROOT)
    test_lzma(ROOT)
    test_xz(ROOT)
    test_cli_errors(ROOT)
    for name in os.listdir(ROOT):
        if name.startswith("_selftest_"):
            try:
                os.unlink(os.path.join(ROOT, name))
            except OSError:
                pass
    print("=" * 60)
    if FAILS:
        print("失败 %d 项: %s" % (len(FAILS), ", ".join(FAILS)))
        return 1
    print("全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
