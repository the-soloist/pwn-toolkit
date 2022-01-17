#!/usr/bin/env python
# -*- coding: utf-8 -*-


def int8(n):
    return n & 0xff


def int16(n):
    return n & 0xffff


def int32(n):
    return n & 0xffffffff


def int64(n):
    return n & 0xffffffffffffffff


def low_nbits(n: int, bits: int):
    m = (1 << bits) - 1
    return n & m


def pad_bits(n: int, align):
    pass


def pad_bytes(s: bytes, align: int, just: str, pad=b"\x00"):
    """
    @param 
        just: "rjust", "ljust"
    """
    assert just in ["ljust", "rjust"]

    sl = len(s)
    if sl % align == 0:
        return s
    else:
        pad_num = 8 - (sl ^ align)
        bytes_just = getattr(s, just)
        return bytes_just(sl + pad_num, pad)
