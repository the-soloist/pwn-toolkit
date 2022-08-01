# PwnT00ls

封装一些常用的功能 \_(:з」∠)\_

## ENV

```
Linux or MacOS
python 3.10.1
```

## INSTALL

```sh
# 安装依赖
pip3 install -r requirements.txt
pip3 install pwntools==4.3.1 --user
pip3 install base58 pybase62 base91 psutil prettytable termcolor tabulate pycryptodome

git clone https://github.com/thenoviceoof/base92 pkg/base92
git clone https://github.com/stek29/base100 pkg/base100

# 导入模块
cd /path/to/PwnT00ls
PT_DIR=$(dirname "$PWD")
export PYTHONPATH="$PYTHONPATH:$PT_DIR"

# 或者 python 中加入
sys.path.append("/path/to/PwnT00ls")

# 修改环境变量
export PATH="$PATH:/path/to/PwnT00ls/bin"
```

## USAGE

```python
from PwnT00ls import *
from pwn import *
```

# REFERENCE

1. https://github.com/ray-cp/pwn_debug
2. https://github.com/pullp/pwn_framework
3. ···
