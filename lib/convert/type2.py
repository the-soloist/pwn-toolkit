#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwnlib.exception import PwnlibException
from typing import Union


def t2bytes(s, encoding="utf-8") -> Union[bytes, bytearray]:
    """ convert to bytes """

    stype = type(s)

    if stype == str:
        return bytes(s, encoding=encoding)
    elif stype == bytes or stype == bytearray:
        return s
    else:
        raise PwnlibException("failed convert to bytes")


def t2str(s, encoding="utf-8") -> str:
    """ convert to str """

    stype = type(s)

    if stype == str:
        return s
    elif stype == bytearray or stype == bytes:
        return s.decode(encoding=encoding)
    else:
        raise PwnlibException("failed convert to str (try encoding='unicode_escape')")


def bytes2int(string, endian="little") -> int:
    """ convert str to int """

    s = t2bytes(string)

    if endian == "little":
        s = s[::-1]
    elif endian == "big":
        pass
    else:
        raise PwnlibException("unsupport type")

    return bytes_to_long(s)


def int2bytes(number, endian="little") -> bytes:
    """ convert int to str """

    s = long_to_bytes(number)

    if endian == "little":
        s = s[::-1]
    elif endian == "big":
        pass
    else:
        raise PwnlibException("unsupport type")

    return s


def char2unicode(c: str) -> str:
    """ 测 -> \u6d4b, 试 -> \u8bd5 """
    
    if c.isascii():
        tmp_ch = hex(ord(c))[2:]
        return "0" * (4 - len(tmp_ch)) + tmp_ch
    else:
        return c.encode("unicode_escape")[2:].decode()