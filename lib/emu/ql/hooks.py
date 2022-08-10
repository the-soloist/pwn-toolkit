#!/usr/bin/env python
# -*- coding: utf-8 -*-

from .utils import is_stack_variable
from qiling import Qiling
from qiling.os.const import POINTER


def strcpy_hook(ql: Qiling):
    max_size = 0x30

    ql.log.info("** Hook [strcpy] **")
    print("return addr %s" % hex(ql.reg.ra))

    params = ql.os.resolve_fcall_params({
        'dest': POINTER,
        'src': POINTER,
    })

    try:
        dest_buf = ql.mem.string(params["dest"])
        src_buf = ql.mem.string(params["src"])
    except:
        dest_buf = ql.mem.read(params["dest"], max_size)
        src_buf = ql.mem.read(params["src"], max_size)

    if is_stack_variable(ql, params["dest"]):
        print("variable defined in stack.")

    print("===== info =====")
    print("dest: ", hex(params["dest"]), bytes(dest_buf[:max_size]), "...")
    print("src: ", hex(params["src"]), bytes(src_buf[:max_size]), "...")
    # print("src_len: %s" % hex(len(src_buf)))
    print("===== end =====\n")

    return dest_buf


def sprintf_hook(ql: Qiling):
    max_size = 0x30

    ql.log.info("** Hook [sprintf] **")
    print("[+] int sprintf(char *str, const char *format, ...)")
    print("return addr %s" % hex(ql.reg.rax))

    params = ql.os.resolve_fcall_params({
        'str': POINTER,
        'format': POINTER,
        'arg1': POINTER,
        'arg2': POINTER,
    })

    try:
        str_buf = ql.mem.string(params["str"])
        format_buf = ql.mem.string(params["format"])
        arg1 = ql.mem.string(params["arg1"])
        arg2 = ql.mem.string(params["arg2"])
    except:
        str_buf = ql.mem.read(params["str"], max_size)
        format_buf = ql.mem.read(params["format"], max_size)
        arg1 = ql.mem.read(params["arg1"], max_size)
        arg2 = ql.mem.read(params["arg2"], max_size)

    if is_stack_variable(ql, params["str"]):
        print("variable defined in stack.")

    print("===== info =====")
    print("str: ", hex(params["str"]), bytes(str_buf[:max_size]), "...")
    print("format: ", hex(params["format"]), bytes(format_buf[:max_size]), "...")
    print("arg1: ", hex(params["arg1"]), bytes(arg1[:max_size]), "...")
    print("arg2: ", hex(params["arg2"]), bytes(arg2[:max_size]), "...")
    print("===== end =====\n")

    return str_buf
