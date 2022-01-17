#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os


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
