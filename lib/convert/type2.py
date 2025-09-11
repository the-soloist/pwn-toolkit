#!/usr/bin/env python

from typing import Union

from Crypto.Util.number import long_to_bytes
from pwnlib.exception import PwnlibException


def var2bytes(s, encoding="utf-8") -> Union[bytes, bytearray]:
    """ convert to bytes """

    stype = type(s)

    if stype == str:
        return bytes(s, encoding=encoding)
    elif stype == bytes or stype == bytearray:
        return bytes(s)
    else:
        raise PwnlibException("failed convert to bytes")


def var2str(b, encoding="utf-8") -> str:
    """ convert to str """

    btype = type(b)

    if btype == str:
        return b
    elif btype == bytearray or btype == bytes:
        return b.decode(encoding=encoding)
    else:
        raise PwnlibException("failed convert to str (try encoding='unicode_escape')")


def str2bytes(s: str, encoding="utf-8") -> Union[bytes, bytearray]:
    return bytes(s, encoding=encoding)


def bytes2str(text: Union[bytes, bytearray], encoding="utf-8") -> str:
    return text.decode(encoding=encoding)


def bytes2int(text: Union[bytes, bytearray], endian="little") -> int:
    s = var2bytes(text)
    return int.from_bytes(s, byteorder="little")


def int2bytes(number: int, endian="little") -> bytes:
    """ convert int to str """

    s = long_to_bytes(number)

    if endian == "little":
        s = s[::-1]
    elif endian == "big":
        pass
    else:
        raise PwnlibException("unsupport type")

    return s


def char2unicodestring(c: str) -> str:
    """ 测 -> \u6d4b -> "6d4b", 试 -> \u8bd5 -> "8bd5" """

    if c.isascii():
        tmp_ch = hex(ord(c))[2:]
        return "0" * (4 - len(tmp_ch)) + tmp_ch
    else:
        return c.encode("unicode_escape")[2:].decode()


def number2bytestring(n):
    """ num -> string -> bytes """
    return str(n).encode()


# alias
b2i = bytes2int
b2s = bytes2str
c2us = char2unicodestring
i2b = int2bytes
n2bs = number2bytestring
s2b = str2bytes
v2b = var2bytes
v2s = var2str
