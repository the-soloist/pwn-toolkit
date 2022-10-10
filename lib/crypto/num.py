#!/usr/bin/env python
# -*- coding: utf-8 -*-


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
        Fjust = getattr(s, just)
        return Fjust(sl + pad_num, pad)
