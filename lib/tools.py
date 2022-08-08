#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import u32, u64, tube, process, remote
from pwn_utils.lib.logger import plog
from string import ascii_letters, digits, punctuation
from typing import Union
import hashlib
import itertools
import os
import random
import re
import sys


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

tube.s = tube.send
tube.sa = tube.sendafter
tube.sl = tube.sendline
tube.sla = tube.sendlineafter
tube.r = tube.recv
tube.rl = tube.recvline
tube.ru = tube.recvuntil
tube.ia = tube.interactive

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


def gen_strings_series(s, n=4, r=False):
    """ s: strings, n: length, r: random"""
    if r == False:
        for i in itertools.product(s, repeat=n):
            yield "".join(i)
    else:
        while True:
            yield "".join(random.sample(s, n))


def crack_hash(mode: str, target: str, prefix="", suffix="", strings=ascii_letters + digits, length=4, random=False):
    """
    @param mode: 哈希函数
    @param target: 目标哈希值
    @param prefix: 前缀
    @param suffix: 后缀
    @param strings: 字符集，默认为大小写字母+数字
    @param length: 爆破长度
    @param random: 随机字典
    """

    from pwn_utils.lib.logger import plog

    if not prefix and not suffix:
        plog.error("Please set prefix or suffix.")

    assert mode in dir(hashlib)

    plog.waitfor(f"cracking: {mode}({' + '.join([x for x in [prefix, '?' * length, suffix] if x])}) == {target}")

    for i in gen_strings_series(strings, length, random):
        plain_text = prefix + i + suffix
        # print(f"test: {plain_text}")
        hash_func = hashlib.__get_builtin_constructor(mode)()
        hash_func.update(plain_text.encode())
        hash_res = hash_func.hexdigest()
        if hash_res == target:
            plog.success(f"found {mode}({plain_text}) == {target}")
            return i

    plog.failure("not found")
    return None
