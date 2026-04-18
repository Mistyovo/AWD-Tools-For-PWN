# AWD-Tools For PWN 使用说明

本仓库中的脚本大多面向 Linux x86_64 ELF（CTF/AWD 场景）。

## 通用准备

1. 进入项目目录：

```bash
cd "AWD-Tools For PWN"
```

2. 建议环境：

- Python 3
- `pwntools`（`pip3 install pwntools`）
- `capstone`（仅 `4.elf-patcher.py` 需要，`pip3 install capstone`）
- Bash 环境（用于 `1.Check_Environment.sh`）

3. 文件名里有空格时，请用引号包裹脚本路径。

---

## 0.exp_templete.py

### 作用
Pwntools EXP 模板，支持本地/远程两种模式，并在交互结束后尝试执行 `cat /flag`。

### 用法

本地模式：

```bash
python3 0.exp_templete.py
```

远程模式：

```bash
python3 0.exp_templete.py <host> <port>
```

### 使用前需要改的地方

- `context.binary = "./pwn"` 改成目标程序路径
- 按题目补充你的利用逻辑（当前文件仅模板结构）

---

## 1.Check_Environment.sh

### 作用
检查常见 PWN 工具是否可用，并给出缺失项。

### 用法

首次执行建议加权限：

```bash
chmod +x 1.Check_Environment.sh
```

检查默认工具清单：

```bash
./1.Check_Environment.sh
```

只检查指定命令：

```bash
./1.Check_Environment.sh python3 gdb checksec
```

---

## 2.add_seccomp.py

### 作用
在**不改变 ELF 文件大小**前提下注入 seccomp 初始化逻辑，支持 No-PIE/PIE。

### 支持范围

- ELF64
- little-endian
- x86_64
- ET_EXEC / ET_DYN

### 用法

```bash
python3 2.add_seccomp.py <input_elf> [output_elf] [--blacklist 列表] [--dry-run]
```

### 参数说明

- `input_elf`：输入 ELF
- `output_elf`：输出 ELF（不写则默认 `<input_elf>.patched`）
- `--blacklist`：黑名单模式，逗号分隔 syscall 名称或编号，例如：`execve,openat,59`
- `--dry-run`：仅分析，不写文件

### 示例

strict 模式（默认）：

```bash
python3 2.add_seccomp.py ./pwn ./pwn.seccomp
```

黑名单模式：

```bash
python3 2.add_seccomp.py ./pwn ./pwn.seccomp --blacklist execve,openat
```

只看计划不落盘：

```bash
python3 2.add_seccomp.py ./pwn --blacklist 59 --dry-run
```

---

## 3.add-pie.py

### 当前状态
该文件目前仅有占位注释（`# 估计过不了Check`），暂无可执行功能。

---

## 4.elf-patcher.py

### 作用
对 x86_64 ELF 做 trampoline patch：

1. 在补丁点写入 `jmp` 跳转
2. 在 code cave 写入“被覆盖指令 + 你的插入代码 + 跳回”
3. 保持文件大小不变

### 用法

```bash
python3 4.elf-patcher.py <file_path> <patch_pos> <insert_code> [-o output] [--offset-mode] [--max-scan N]
```

### 参数说明

- `patch_pos`：默认按 VA（虚拟地址）解释，支持十进制/`0x`
- `--offset-mode`：将 `patch_pos` 按文件偏移解释
- `insert_code`：十六进制机器码，如 `5058` 或 `\x50\x58`
- `--max-scan`：补丁点附近反汇编窗口，默认 `64`

### 示例

按 VA 打补丁：

```bash
python3 4.elf-patcher.py ./pwn 0x40123a 5058 -o ./pwn.patched
```

按文件偏移打补丁：

```bash
python3 4.elf-patcher.py ./pwn 0x123a 5058 --offset-mode -o ./pwn.patched
```

---

## 6.Traffic_Reply.py

### 作用
两种模式：

1. `patch`：给 ELF 注入流量镜像逻辑（hook read/write 等）
2. `receiver`：本地启动接收端，把镜像流量写入日志

### patch 模式

```bash
python3 6.Traffic_Reply.py patch <input_elf> [output_elf] --collector-ip <ip> --collector-port <port> [--max-payload N] [--dry-run]
```

参数说明：

- `--collector-ip`：接收端 IPv4
- `--collector-port`：接收端端口
- `--max-payload`：每次 read/write 镜像的最大字节数（默认 `1024`）
- `--dry-run`：仅分析，不写文件

### receiver 模式

```bash
python3 6.Traffic_Reply.py receiver --listen-port <port> [--listen-ip 0.0.0.0] [--log-file traffic_capture.log] [--max-frame 262144] [--preview-bytes 128] [--silent]
```

参数说明：

- `--listen-port`：监听端口（必填）
- `--log-file`：日志文件（默认 `traffic_capture.log`）
- `--preview-bytes`：日志里 text/hex 预览长度
- `--silent`：不在终端实时打印，仅写日志

### 典型流程

1. 先开接收端：

```bash
python3 6.Traffic_Reply.py receiver --listen-port 9001
```

2. 再打补丁：

```bash
python3 6.Traffic_Reply.py patch ./pwn ./pwn.traffic --collector-ip 127.0.0.1 --collector-port 9001
```

---

## 8.Batch Attack.py

### 作用
批量调用 EXP，对 `hosts x ports` 组合进行攻击；从输出中匹配关键字并把结果写入 `flags.txt`。

### 使用前需要改的地方

- `hosts = []` 填入目标主机列表
- `ports = []` 填入目标端口列表
- `exp = "exp.py"` 改成你的 EXP 文件名
- `key_word = "FOUND FLAG: "` 与 EXP 输出关键字保持一致

### 用法

```bash
python3 "8.Batch Attack.py"
```

### 输出

命中关键字时，会追加写入：`flags.txt`

---

## 9.Submit_Flag.py

### 当前状态
该文件目前仅有 `from pwn import *`，尚未实现提交逻辑。

---

## 建议

- 先用 `1.Check_Environment.sh` 做环境检查
- 正式打补丁前先加 `--dry-run` 看可行性
- 对二进制脚本处理前先备份原文件