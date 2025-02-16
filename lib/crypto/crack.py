#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import itertools
import random
import string
from pwnlib.util.iters import bruteforce, mbruteforce

from pwnkit.lib.log import plog

__all__ = [
    "gen_strings_series",
    "do_hash_pow",
    "do_hash_pow_m",
]


default_string_table = string.ascii_letters + string.digits


def gen_strings_series(s, n=4, method="fixed"):
    """ s: strings, n: length, method: fixed/random"""
    if method == "fixed":
        for i in itertools.product(s, repeat=n):
            yield "".join(i)
    elif method == "random":
        while True:
            yield "".join(random.sample(s, n))
    raise ValueError(f"Invalid generation method: {method}")


def do_hash_pow(mode: str, target: str, prefixes="", suffixes="", strings=default_string_table, strmethod="fixed", length=4):
    """
    Arguments:
      mode: 哈希函数
      target: 目标哈希值
      prefixes: 前缀
      suffixes: 后缀
      strings: 字符集，默认为大小写字母+数字
      strmethod: 生成方式 (fixed/random)
      length: 未知内容长度
      random: 字典顺序随机生成

    Returns:
      目标字符串（不含 salt 部分）

    Example:
      >>> mode, unknown, salt, target = (x.decode() for x in re.split(b"[\(\)+= \n]", p.ru(b"\n")) if x)
      >>> res = do_hash_pow(mode, target, prefixes="xxx", suffixes=salt, strmethod="fixed", length=6)
    """

    assert mode in dir(hashlib), f"Unsupported hash algorithm: {mode}"

    plog.waitfor(f"Cracking: {mode}('{prefixes}' + '{"?"*length}' + '{suffixes}') == {target}")

    for i in gen_strings_series(strings, length, method=strmethod):
        content = prefixes + i + suffixes
        obj = hashlib.__get_builtin_constructor(mode)()
        obj.update(content.encode())

        if obj.hexdigest() == target:
            plog.success(f"Found {mode}({content}) == {target}")
            return i

    plog.failure("No solution found")
    return None


def do_hash_pow_m(mode: str, target: str, prefixes="", suffixes="", strings=default_string_table, strmethod="upto", length=6, threads=16):
    """
    Arguments:
      mode: 哈希函数
      target: 目标哈希值
      prefixes: 前缀
      suffixes: 后缀
      strings: 字符集，默认为大小写字母+数字
      strmethod: 同 mbruteforce 的 method 参数 (fixed/upto/downfrom)
      length: 字符串长度
      threads: 线程数

    Example:
      >>> mode, unknown, salt, target = (x.decode() for x in re.split(b"[\(\)+= \n]", p.ru(b"\n")) if x)
      >>> res = do_hash_pow_m(mode, target, prefixes="xxx", suffixes=salt, length=8)
    """

    assert mode in dir(hashlib), f"Unsupported hash algorithm: {mode}"

    plog.waitfor(f"Cracking: {mode}('{prefixes}' + '{"?"*length}' + '{suffixes}') == {target}")

    def brute(cur: str) -> bool:
        content = prefixes + cur + suffixes  # cur is already a string
        obj = hashlib.__get_builtin_constructor(mode)()
        obj.update(content.encode())
        return obj.hexdigest() == target

    res = mbruteforce(brute, strings, method=strmethod, length=length, threads=threads)

    if res:
        plog.success(f"Found {mode}({prefixes}{res}{suffixes}) == {target}")
    else:
        plog.failure("No solution found")
    return res
