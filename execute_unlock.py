import usb.core
import usb.util
import sys
import os

def execute_unlock():
    # 也可以直接把下面的 input 改成 "unlock_payload.txt"
    payload_file = input("请输入 unlock_payload.txt 的完整路径: ").strip().strip('"').strip("'")
    
    if not os.path.exists(payload_file):
        print(f"[-] 找不到文件: {payload_file}")
        sys.exit(1)
        
    try:
        with open(payload_file, "r") as f:
            hex_data = f.read().strip()
            packet = bytes.fromhex(hex_data)
        print(f"[+] 成功加载载荷，大小: {len(packet)} 字节")
    except Exception as e:
        print(f"[-] 读取或解析失败: {e}")
        sys.exit(1)

    print("[*] 正在寻找 Fastboot 设备...")
    dev = usb.core.find(idVendor=0x18d1, idProduct=0x0d00)
    if dev is None:
        dev = usb.core.find(idVendor=0x05c6, idProduct=0x9008)
        
    if dev is None:
        print("[-] 未找到设备，请确保手机处于 Fastboot 模式并连接电脑")
        sys.exit(1)
        
    print(f"[+] 找到设备: {dev.idVendor:04x}:{dev.idProduct:04x}")

    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except Exception:
        pass
        
    dev.set_configuration()

    print("[*] 正在发送解锁指令...")
    try:
        dev.write(0x01, packet)
        print("[+] 解锁载荷发送成功！")
        try:
            resp = dev.read(0x81, 64, timeout=2000)
            print(f"[+] 设备响应: {bytes(resp).decode('utf-8', errors='ignore')}")
        except Exception:
            print("[+] 发送完毕，等待设备处理...")
    except usb.core.USBError as e:
        print(f"[-] 通信结束: {e}")

if __name__ == "__main__":
    execute_unlock()