# legacy/ —— 已废弃的原始脚本

这两个文件是仓库最初的版本，从酷安帖子转写而来。**保留它们只为对照，不要运行。**

| 文件 | 原本的作用 | 为什么留着 |
| --- | --- | --- |
| `gen_payload.py` | 从 `abl_raw.img` 里扫"特征码"、拼 `unlock_payload.txt` | 展示"特征码/偏移/地址"三处互相矛盾 |
| `execute_unlock.py` | 用 pyusb 把 payload 写到 `0x01` 端点 | 展示包格式错误与 9008 回退 |

逐条错误分析见 [../docs/findings.md](../docs/findings.md)。

如果你想分析自己的 `abl` 镜像，用仓库根目录的 [`analyze_abl.py`](../analyze_abl.py)：
它只读文件，既不连接设备，也不发送任何 USB 数据。
