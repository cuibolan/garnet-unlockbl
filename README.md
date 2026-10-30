# garnet-unlockbl
帮助redminote13pro5g用户强解BL

来自酷安@旋冰狼and
漏洞原理:
在处理 fastboot oem unlock 命令时 (反汇编偏移 0x62e40 附近)，代码完全没有校验传入参数的长度！它直接执行 add w0, w8, 4 并调用 AllocatePool。
更致命的是，底层 Fastboot 分配了一个高达 64KB (0x10000) 的接收缓冲区，且未开启 HeapGuard (堆保护)。
只要我们伪造一个 0xFFFFFFFF 的长度头，就能触发 32 位整数溢出，强制系统分配 0 字节，然后把 64KB 的恶意载荷全部覆盖到相邻的内存结构上。

利用方式:
通过堆溢出覆盖 x24 指针，劫持 UEFI 虚表跳转 (br x8)，强行执行我们自己写的 AArch64 Shellcode，把控制解锁的全局标志位 0xd99d7 直接覆盖成 0。
准备环境:

1. 电脑装好 Python。
2. pip install pyusb (Windows 记得用 Zadig 把 Fastboot 驱动换成 WinUSB)。
3. 手机进 Fastboot，插上电脑。
