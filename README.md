# PwnT00ls

封装一些常用的功能 \_(:з」∠)\_ 

## ENV

```
Linux or MacOS
python 3.10.1
```

## INSTALL
安装依赖
```sh
pip3 install pwntools qiling winpwn \
    pycryptodome base58 pybase62 base91 \
    redis ipdb psutil \
    colorama loguru tqdm

git clone https://github.com/thenoviceoof/base92 pkg/base92
git clone https://github.com/stek29/base100 pkg/base100
```
```sh
cd /path/to/PwnT00ls
PT_PATH=$(dirname "$PWD")
export PYTHONPATH=$PYTHONPATH:$PT_PATH
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
