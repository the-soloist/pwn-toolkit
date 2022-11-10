#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import itertools
import random
from string import ascii_letters, digits, punctuation


def gen_strings_series(s, n=4, r=False):
    """ s: strings, n: length, r: random"""
    if r == False:
        for i in itertools.product(s, repeat=n):
            yield "".join(i)
    else:
        while True:
            yield "".join(random.sample(s, n))


def do_hash_pow(mode: str, target: str, prefix="", suffix="", strings=ascii_letters + digits, length=4, random=False):
    """
    @param mode: 哈希函数
    @param target: 目标哈希值
    @param prefix: 前缀
    @param suffix: 后缀
    @param strings: 字符集，默认为大小写字母+数字
    @param length: 爆破长度
    @param random: 随机字典

    usage:
        >>> mode, unknown, salt, target = (x for x in re.split(b"[\(\)+= \n]", p.ru("\n")) if x)
        >>> res = do_hash_pow(mode.decode(), target.decode(), suffix=salt.decode())
    """

    from pwnutils.lib.logger import plog

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
