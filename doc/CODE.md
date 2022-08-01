# CODE

## debug python

```python
import ipdb; ipdb.set_trace()
```

## print local address

```python
from pf.osys.linux.elf.maps import *

### print text base and libc base
text_base, libc_base = util.maps.get_base(sh=sh)  # get_base(libs=sh.libs(), elf=elf)
paddr("text_base", text_base)
paddr("libc_base", libc_base)

### print heap base
heap_base = int("0x%s" % get_heap_map(sh).addr.split("-")[0], 16)
paddr("heap_base", heap_base)

# assert hex(brute_addr)[-4:] == "ffff"  # 1/16
```

## brute-force attack

```python
### the following code is used for brute-force attack
for _ in range(0x10):
    try:
        sh = pwnpwnpwn(args)
        exploit(sh)
    except Exception as e:
        # logger.log("ALERT", str(e.__class__))
        traceback.print_exc()
        sh.close()
    else:
        break
```

## compile symbol file

```python
### compile symbol file
salt = get_salt()
gdb_symbol_file = compile_symbol_file("./http_struct.c")
GDBSCRIPT += f"\nadd-symbol-file {symbol_file}\n"
# sh = process([ld.path, elf.path], env={"LD_PRELOAD": gdb_symbol_file})
pdebug(sh, GDB_SCRIPT)
```

## os.path / pathlib

```python
os.path.dirname(os.path.realpath(__file__))
os.path.split(os.path.realpath(__file__))
```

[Python 获取当前文件路径](https://www.jianshu.com/p/bfa29141437e)

[Python3 中使用 Pathlib 模块进行文件操作](https://cuiqingcai.com/6598.html)

## add symbol file

```python
from PwnT00ls.utils.compiler import *

symbol_file = compile_symbol_file("./symbols.c")

GDB_SCRIPT = f"""
add-symbol-file {symbol_file}
""".strip()
```

## crack hash

```python
p.recvuntil(b"prefix: ")
prefix = p.recvuntil(b"\n", drop=True).decode()
p.recvuntil(b"target: ")
target = p.recvuntil(b"\n", drop=True).decode()
res = crack_hash("sha256", target, prefix=prefix, strings=printable, length=3)
p.sendlineafter("input: ", res)
```
