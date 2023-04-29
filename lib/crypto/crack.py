#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import itertools
import random
import string
from pwnlib.util.iters import bruteforce, mbruteforce
from pwnutils.lib.logger import plog


__all__ = [
    "gen_strings_series",
    "do_hash_pow",
    "do_hash_pow_m",
]


default_string_table = string.ascii_letters + string.digits


def gen_strings_series(s, n=4, r=False):
    """ s: strings, n: length, r: random"""
    if r == False:
        for i in itertools.product(s, repeat=n):
            yield "".join(i)
    else:
        while True:
            yield "".join(random.sample(s, n))


def do_hash_pow(mode: str, target: str, prefixes="", suffixes="", strings=default_string_table, length=4, random=False):
    """
    Arguments:
      mode: 哈希函数
      target: 目标哈希值
      prefixes: 前缀
      suffixes: 后缀
      strings: 字符集，默认为大小写字母+数字
      length: 未知内容长度
      random: 字典顺序随机生成

    Returns:
      目标字符串（不含 salt 部分）

    Example:
      >>> mode, unknown, salt, target = (x.decode() for x in re.split(b"[\(\)+= \n]", p.ru(b"\n")) if x)
      >>> res = do_hash_pow(mode, target, suffixes=salt)
    """

    assert not prefixes and not suffixes
    assert mode in dir(hashlib)

    plog.waitfor(f"cracking: {mode}({' + '.join([x for x in [prefixes, '?' * length, suffixes] if x])}) == {target}")

    for i in gen_strings_series(strings, length, random):
        content = prefixes + i + suffixes
        # print(f"test: {content}")
        obj = hashlib.__get_builtin_constructor(mode)()
        obj.update(content.encode())
        if obj.hexdigest() == target:
            plog.success(f"found {mode}({content}) == {target}")
            return i

    plog.failure("not found")
    return None


def do_hash_pow_m(mode: str, target: str, prefixes="", suffixes="", strings=default_string_table, strmethod="upto", length=6, thread=16):
    """
    Arguments:
      mode: 哈希函数
      target: 目标哈希值
      prefixes: 前缀
      suffixes: 后缀
      strings: 字符集，默认为大小写字母+数字
      strmethod: 同 mbruteforce 的 method 参数
      length: 字符串长度
      thread: 线程数

    Example:
      >>> mode, unknown, salt, target = (x.decode() for x in re.split(b"[\(\)+= \n]", p.ru(b"\n")) if x)
      >>> res = do_hash_pow_m(mode, target, suffixes=salt)
    """

    assert not prefixes and not suffixes
    assert mode in dir(hashlib)

    def brute(cur):
        content = prefixes + str(cur) + suffixes
        obj = hashlib.__get_builtin_constructor(mode)()
        obj.update(content.encode())
        if obj.hexdigest() == target:
            return True
        return False

    res = mbruteforce(brute, strings, method=strmethod, length=length, threads=thread)
    return res
