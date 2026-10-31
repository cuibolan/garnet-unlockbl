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

第一步：提取镜像与生成 Payload
执行gen_payload.py


第二步：通过 USB 发送 Payload(自己手动改一下脚本里的payload.txt路径)
执行execute_unlock.py

预期结果:
如果一切完美，发送完之后设备可能会直接黑屏重启，或者 fastboot 状态改变，最理想的情况是不崩溃，直接解锁；不过目前只本地测试了红米 note13Pro5G版(特别注意，这个是5G,不是4G的),如果确保是同个机型，在确保版本相同，比如我现在就是3.0.306的澎湃版本,所以特别建议同一个版本，这样子成功率会高一点
