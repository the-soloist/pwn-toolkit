#!/usr/bin/env python
# -*- coding: utf-8 -*-

from PwnT00ls.lib.convert.type2 import bytes2int, t2bytes


def bytes2mem(string, mode=64, endian="little"):
    """ Usage:
    
    bytes2mem("/path/to/flag", 64, "little") -> [0x6f742f687461702f, 0x67616c662f]
    """

    assert mode % 8 == 0
    bytes_align = mode // 8
    res = []
    string = t2bytes(string)

    for i in range(len(string) // bytes_align + 1):
        s = string[i * bytes_align:(i + 1) * bytes_align]
        n = bytes2int(s, endian)
        res.append(n)

    return res
