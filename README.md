# pwnutils

自用的一个做 pwn 题的 python 库，封装一些常用的函数。

## ENV

```
Linux or MacOS
python 3.10.x
```

## INSTALL

```sh
# 安装依赖
pip3 install -r requirements.txt
# pip3 install pwntools==4.3.1
pip3 install pybase62 prettytable termcolor tabulate pycryptodome websocket-client

git clone https://github.com/thenoviceoof/base92 pkg/base92
git clone https://github.com/stek29/base100 pkg/base100

# 导入模块
git clone https://github.com/the-soloist/pwn-utils pwnutils
export PYTHONPATH="$PYTHONPATH:/path/to/pwnutils"

# 或者 python 中加入
sys.path.append("/path/to/pwnutils")

# 修改环境变量
export PATH="$PATH:/path/to/pwnutils/bin"
```

## USAGE

```python
from pwnutils import *
```

使用文档：[doc](doc) （未完成）

# REFERENCE

1. https://github.com/ray-cp/pwn_debug
2. https://github.com/pullp/pwn_framework
3. ···
