## 命令行参数与配置

### 模板

`exploit.py` 模板：

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# repo: https://github.com/the-soloist/pwn-toolkit

from pwnkit import *

args = init_pwn_args()
binary = ELF("./binary")
args.info.binary = context.binary = binary
args.info.target = ("example.server", 9999)

GDB_SCRIPT = """ """

p = pwntube(args)

# p.dbg(GDB_SCRIPT)
p.interactive()
p.close()
```

### 命令行参数

```shell
> python exploit.py -h
usage: exploit.py [-h] (-d | -l | -r | -s | -w) [-v] {awd} ...

positional arguments:
  {awd}            sub command
    awd            awd help

options:
  -h, --help       show this help message and exit
  -d, --debug
  -l, --local
  -r, --remote
  -s, --ssh
  -w, --websocket
  -v, --verbose
```

- 启动模式：
  - debug：通过 `gdb.debug()` 启动，可设置 cmd 与 kwargs
  - local：通过 `process()` 启动，可设置 cmd 与 kwargs
  - remote：通过 `remote()` 启动
  - ssh：通过 `ssh()` 启动，需要设置 `args.env.ssh` 参数
  - websocket：同 remote 模式

### 本地调试

通过 `process()` 启动，在 `exploit.py` 中进行如下配置：

```python
binary = ELF("/path/to/binary")
```

可选配置：`args.env.cmd`、`args.env.kwargs`

如：运行指定版本的 libc

```python
ld = ELF("/path/to/ld.so")
args.env.cmd = [ld.path, binary.path]
args.env.kwargs = { "env": {"LD_PRELOAD": "/path/to/libc.so"}, }
```

命令行运行：

```shell
python exploit.py -l
```

### Qemu 模拟调试

通过 `process()` 启动，`exploit.py` 配置：

```python
args.env.cmd = [f"qemu-{context.arch}", "-g", "9999", "-L", ".", binary.path]
...
GDB_SCRIPT += "\n" + "file /path/to/binary"
GDB_SCRIPT += "\n" + "target remote :9999"
```

或者

```python
args.env.cmd = ["./run.sh"]
...
GDB_SCRIPT += "file /path/to/binary"
GDB_SCRIPT += "target remote :9999"
```

```shell
> cat ./run.sh
#!/bin/bash
qemu-mips -g 9999 -L . /path/to/binary
```

命令行运行：

```shell
python exploit.py -l
```

### GDB 调试模式

通过 `gdb.debug()` 启动，`exploit.py` 配置：

```python
args.env.kwargs = {"gdbscript": GDB_SCRIPT, }
```

命令行运行：

```shell
python exploit.py -d
```

### 远程调试

通过 `ssh()` 启动，`exploit.py` 配置：

```python
args.env.ssh = ssh("username", "example.pwnme", port=22, password="password")
args.env.cmd = ["/path/to/binary"]
args.env.kwargs = {}
```

ssh 的使用方式参考[官方文档](https://docs.pwntools.com/en/stable/tubes/ssh.html)

命令行运行：

```shell
python exploit.py -s
```

- `args.env.cmd`：填写远程服务器中，待执行文件的绝对路径

### 远程连接

支持模式：remote、websocket

`exploit.py` 配置：

```python
args.info.target = ("example.server", 9999)
```

命令行运行：

```shell
# remote
python exploit.py -r
# websocket
python exploit.py -w
```
