#!/usr/bin/env python
# -*- coding: utf-8 -*-
# reference:
#   1. https://xuanxuanblingbling.github.io/ctf/tools/2021/01/10/bu/

from pwn_utils.lib.logger import plog
import struct


def uint8(n):
    return n & 0xff


def uint16(n):
    return n & 0xffff


def uint32(n):
    return n & 0xffffffff


def uint64(n):
    return n & 0xffffffffffffffff


def uintX(n, bits):
    """ uint: unsigned int """
    return n & ((1 << bits) - 1)


def sintX(n, bits):
    """ sint: signed int """
    pass


def float2hex(f: float) -> int:
    return struct.unpack("<I", struct.pack("<f", f))[0]


def double2hex(f: float) -> int:
    return struct.unpack('<Q', struct.pack('<d', f))[0]


def hex2float(n: int) -> float:
    return struct.unpack("<f", struct.pack("<I", n))[0]


def hex2double(n: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", n))[0]


class Number(object):
    def __init__(self, n, bits, ntype=None):
        self.n = n
        self.num = None
        self.ntype = ntype
        self.bits = bits
        self.nrange = dict()
        self.check()

    def check(self):
        assert self.bits % 8 == 0

        if not self.ntype:
            self.ntype = type(self.n).__name__
        if self.ntype == "float" and self.bits == 64:
            self.ntype = "double"

        self.nrange["min_signed"] = -(1 << self.bits - 1) + 1
        self.nrange["max_signed"] = 1 << self.bits - 1
        self.nrange["max_unsigned"] = (1 << self.bits - 1) - 1

        self.num = Number.n2int(self.n, self.bits)

    def n2int(n, bits):
        assert bits % 8 == 0
        if type(n) == int:  # int
            return uintX(n, bits)
        elif type(n) == float and bits == 32:  # float
            return float2hex(n)
        elif type(n) == float and bits == 64:  # double
            return double2hex(n)

    def h2float(n, bits):
        assert bits <= 32 and bits % 8 == 0
        return hex2float(n)

    def h2double(n, bits):
        assert bits <= 64 and bits % 8 == 0
        return hex2double(n)

    def show(self):
        print("input:        ", self.n)
        print("hex:          ", hex(self.num))
        print("bin:          ", bin(self.num))
        print("--------------------------------------------------")
        print("bits:         ", self.bits)
        print("min signed:   ", hex(self.nrange["min_signed"]), self.nrange["min_signed"])
        print("max signed:   ", hex(self.nrange["max_signed"]), self.nrange["max_signed"])
        print("max unsigned: ", hex(self.nrange["max_unsigned"]), self.nrange["max_unsigned"])

        if self.ntype == "hex":
            print("--------------------------------------------------")
            if self.bits == 32:
                print("float:        ", Number.h2float(self.n, self.bits))
            elif self.bits == 64:
                print("double:       ", Number.h2double(self.n, self.bits))
