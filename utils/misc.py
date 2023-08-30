#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from pwn import u8, u16, u32, u64, process, remote


__all__ = [
    "uu8", "uu16", "uu32", "uu64",
    "dump_remote_binary",
    "get_salt",
    "compile_symbol_file"
]


uu8 = u8
uu16 = lambda data: u16(data.ljust(2, b"\x00"))
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
