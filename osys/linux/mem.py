#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwnkit.lib.convert.type2 import b2i, v2b


def bytes2mem(string, mode=64, endian="little"):
    """ Usage:

    bytes2mem("/path/to/flag", 64, "little") -> [0x6f742f687461702f, 0x67616c662f]
    """

    assert mode % 8 == 0
    bytes_align = mode // 8
    res = []
    string = v2b(string)

    for i in range(len(string) // bytes_align + 1):
        s = string[i * bytes_align:(i + 1) * bytes_align]
        n = b2i(s, endian)
        res.append(n)

    return res
