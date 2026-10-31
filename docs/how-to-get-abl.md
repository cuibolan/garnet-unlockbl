# 怎么拿到一份可分析的 abl 镜像

`analyze_abl.py` 需要 `abl` 分区的镜像。有两条路，优先走第一条。

---

## 路线 A：官方固件包（推荐）

不用手机、不用 root、不动设备，拿到的是和出厂完全一致的镜像，最适合交叉验证。

1. 下对应机型/版本的小米 HyperOS fastboot 包（`*.tgz`，里面是 `images/` 目录）。
2. 解压后在 `images/` 里找 `abl.elf`（有的是 `abl.elf` + `abl.img`）。
3. 直接分析：

```bash
python analyze_abl.py images/abl.elf --json abl.report.json -v
```

`abl.elf` 通常是标准 ELF64（AArch64），工具会按程序头做 VA 映射，
报告里的地址就是固件里的链接地址，可以直接和帖子里的 `0xd99d5` 之类对照。

**优点**：无需 root、无风险、可复现（别人下同一个包得到的 SHA-256 和你一样）。
**缺点**：只能看到"出厂是什么样"，看不到你手机上实际跑的那份（如果 OTA 增量更新过，
`abl_a` 可能已经变了）。

---

## 路线 B：手机上直接 dump（需要 root）

前提是你已经有 root。注意：**有 root 不等于解了 BL**——小米设备上存在通过系统服务
（如 `miui.mqsas.IMQSNative`）以 uid=0 执行代码、再加载 KernelSU LKM 的免解锁方案
（例：[mi_nobl_root](https://github.com/mrdong916/mi_nobl_root)）。
这条路能拿到镜像，但**不改变"能不能解锁"这件事**，两者是不同的问题。

```bash
# 1. 确认分区名（不同机型可能是 abl_a / abl / abl_b）
adb shell "su -c 'ls -l /dev/block/by-name/ | grep -i abl'"

# 2. 只读 dump（dd 不会写入分区，安全）
adb shell "su -c 'dd if=/dev/block/by-name/abl_a of=/sdcard/abl_a.img bs=1M'"

# 3. 取回
adb pull /sdcard/abl_a.img

# 4. 分析
python analyze_abl.py abl_a.img --json abl_a.report.json -v
```

**优点**：拿到的是你机器上真正在跑的那一份。
**缺点**：依赖 root，而免 BL 的临时 root 方案通常绑定特定系统版本，
重启失效，OTA 可能修复。

### 风险边界

- `dd if=...` 是**只读**，不会改动分区；`of=` 指向 `/sdcard`，也不碰系统。
- 真正有风险的是**同一套 root 去执行来路不明的 payload**（比如网盘里那个
  `unlock_payload.txt` + 发包脚本），那是往 bootloader 写数据，和 dump 是两件事。
- 免 BL root 方案一般需要 `insmod` 第三方 `.ko`，等于把内核交给那个模块。
  只在你愿意承担风险的设备上做，并且优先选开源、能读懂的实现。

---

## 取证规范（写报告时用）

为了让别人能复现，dump 完至少记下这些：

```bash
adb shell getprop ro.product.device            # garnet
adb shell getprop ro.build.version.release     # 例如 15 / 16
adb shell getprop ro.build.version.incremental # 例如 OS3.0.306.0...
adb shell getprop ro.build.display.id
sha256sum abl_a.img                            # 或 certutil -hashfile abl_a.img SHA256
```

把这些和 `analyze_abl.py` 生成的 `abl.report.json` 放一起，
报告里的每个地址才有意义——换一个版本，地址和指令都可能变。

---

## 拿到镜像之后看什么

1. **「溢出特征码」一节**：`08 c3 5e b8 / 00 11 00 11` 在不在，实际解码成什么。
2. **「字符串引用」一节**：引用 `oem unlock` 的 `adrp+add` 在哪个地址——
   从这里向上找函数入口，就是 fastboot 命令处理逻辑。
3. **「ldrb 读取点」一节**：有没有 `[x8, #0xd]` 这类读取，目标地址是多少。
4. **「传说地址是否在镜像内」**：帖子那三个地址 + `0x40000000` 到底落不落在映射范围内。

第 1、2 条能给出的结论是"帖子说的指令/代码位置存不存在"，**不是**"漏洞成不成立"。
后者需要看长度字段有没有校验、缓冲区多大、溢出能覆盖到什么——那是下一步的事。
