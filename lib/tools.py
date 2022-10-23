#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os
from pwn import u32, u64, process, remote
from pwnutils.lib.logger import plog


""" 
s = lambda data: sh.send(data)
sa = lambda delim, data: sh.sendafter(delim, data)
sl = lambda data: sh.sendline(data)
sla = lambda delim, data: sh.sendlineafter(delim, data)
r = lambda numb=0x1000: sh.recv(numb)
rl = lambda keepends=True: sh.recvline(keepends)
ru = lambda delims, drop=False: sh.recvuntil(delims, drop)

plog = lambda x: log.success('%s >> %s' % (x, hex(eval(x)))) if type(eval(x)) == int else log.success('%s >> %s' % (x, eval(x)))
paddr = lambda name, value: log.success("%s -> 0x%x" % (name, value))
pinfo = lambda *args, end=" ": log.info(("%s" % end).join([str(x) for x in args]))
psucc = lambda *args, end=" ": log.success(("%s" % end).join([str(x) for x in args]))
"""


uu32 = lambda data: u32(data.ljust(4, b"\x00"))
uu64 = lambda data: u64(data.ljust(8, b"\x00"))


def get_base_name(_file):
    return os.path.basename(_file)


def get_func_name(_frame):
    return _frame.f_code.co_name


def dump_remote_binary(sh, output, prefix, suffix):
    sh.recvuntil(prefix, drop=True)
    data = sh.recvuntil(suffix, drop=True)
    open(output, "wb").write(data)
    return data


def get_salt():
    """ salt = get_salt() """
    return os.getenv("GDB_SALT") if (os.getenv("GDB_SALT")) else ""


def compile_symbol_file(src_file, salt="", arch=64):
    temp_file_name = "/tmp/gdb_symbols{}".format(salt)
    temp_file_path = f"{temp_file_name}.c"
    temp_so_path = f"{temp_file_name}.so"

    os.system(f"cp {src_file} {temp_file_path}")

    if arch == 64:
        payload = f"gcc -g -shared {temp_file_path} -o {temp_so_path}"
        os.system(payload)
    if arch == 32:
        payload = f"gcc -g -m32 -shared {temp_file_path} -o {temp_so_path}"
        os.system(payload)

    return f"{temp_so_path}"
