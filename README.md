# pwn-toolkit

自用的一个做 pwn 题的 python 库，封装一些常用的函数。

实现思路是在 python 脚本中配置参数，然后可以通过命令行参数切换运行模式。

目前支持模式：

- debug（[gdb.debug](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/gdb.py)）
- local（[pwnlib.tubes.process](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/tubes/process.py)）
- remote（[pwnlib.tubes.remote](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/tubes/remote.py)，可以搭配[debug-server](https://github.com/Ex-Origin/debug-server)进行远程调试
- ssh（[pwnlib.tubes.ssh](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/tubes/ssh.py)，推荐和[pwn-env-docker](https://github.com/the-soloist/pwn-env-docker) 结合使用）
- websocket（[websocket-client](https://github.com/websocket-client/websocket-client)）

## TODO

- [ ] 自动上传附件到 SSH，深度结合 pwn-env-docker

## ENV

```
Linux or MacOS
python 3.10.x
```

## INSTALL

```sh
# 安装依赖
./install.sh

# 导入模块
git clone https://github.com/the-soloist/pwn-toolkit pwnkit
export PYTHONPATH="$PYTHONPATH:/path/to/pwnkit"

# 或者 python 中加入
sys.path.append("/path/to/pwnkit")

# 修改环境变量
export PATH="$PATH:/path/to/pwnkit/bin"
```

## USAGE

```python
from pwnkit import *
```

详细使用文档：[docs](docs) （未完成）

## REFERENCE

1. https://github.com/ray-cp/pwn_debug
2. https://github.com/pullp/pwn_framework
3. ···
