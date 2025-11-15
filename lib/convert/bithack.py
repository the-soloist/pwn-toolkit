#!/usr/bin/env python

import ctypes
import struct
from typing import Dict, Optional, Union


def uint8(n: int) -> int:
    return n & 0xff


def uint16(n: int) -> int:
    return n & 0xffff


def uint32(n: int) -> int:
    return n & 0xffffffff


def uint64(n: int) -> int:
    return n & 0xffffffffffffffff


def uintX(n: int, bits: int) -> int:
    """Unsigned integer with specified bit length"""
    return n & ((1 << bits) - 1)


def sintX(n: int, bits: int) -> int:
    """Convert a number to signed integer with specified bit length"""
    mask = (1 << bits) - 1
    sign_bit = 1 << (bits - 1)
    if n & sign_bit:  # If sign bit is set
        return n | ~mask  # Extend sign bits
    return n & mask  # Positive number


def float2hex(f: float) -> int:
    return struct.unpack("<I", struct.pack("<f", f))[0]


def double2hex(f: float) -> int:
    return struct.unpack('<Q', struct.pack('<d', f))[0]


def hex2float(n: int) -> float:
    return struct.unpack("<f", struct.pack("<I", n))[0]


def hex2double(n: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", n))[0]


def c_hex2float(hex_value):
    # 方式1: 使用 c_uint32 和 c_float
    i = ctypes.c_uint32(hex_value)
    f = ctypes.cast(ctypes.pointer(i), ctypes.POINTER(ctypes.c_float))
    return f.contents.value


def c_hex2double(hex_value):
    # 使用 c_uint64 和 c_double
    i = ctypes.c_uint64(hex_value)
    d = ctypes.cast(ctypes.pointer(i), ctypes.POINTER(ctypes.c_double))
    return d.contents.value


class Number:
    """Class for handling numbers with different bit lengths and types"""

    def __init__(self, n: Union[int, float], bits: int, ntype: Optional[str] = None):
        self.n = n
        self.num: Optional[int] = None
        self.ntype = ntype
        self.bits = bits
        self.nrange: Dict[str, int] = {}
        self.check()

    def check(self) -> None:
        assert self.bits % 8 == 0, "Bit length must be multiple of 8"

        if not self.ntype:
            self.ntype = type(self.n).__name__
        if self.ntype == "float" and self.bits == 64:
            self.ntype = "double"

        self.nrange["min_signed"] = -(1 << (self.bits - 1))
        self.nrange["max_signed"] = (1 << (self.bits - 1)) - 1
        self.nrange["max_unsigned"] = (1 << self.bits) - 1

        self.num = self.n2int(self.n, self.bits)

    @staticmethod
    def n2int(n: Union[int, float], bits: int) -> int:
        assert bits % 8 == 0, "Bit length must be multiple of 8"
        if isinstance(n, int):
            return uintX(n, bits)
        elif isinstance(n, float):
            if bits == 32:
                return float2hex(n)
            elif bits == 64:
                return double2hex(n)
        raise ValueError("Unsupported number type")

    @staticmethod
    def h2float(n: int, bits: int) -> float:
        assert bits <= 32 and bits % 8 == 0, "Bit length must be <= 32 and multiple of 8"
        return hex2float(n)

    @staticmethod
    def h2double(n: int, bits: int) -> float:
        assert bits <= 64 and bits % 8 == 0, "Bit length must be <= 64 and multiple of 8"
        return hex2double(n)

    def show(self) -> None:
        """Display number information in a formatted way"""
        print(f"Input:        {self.n}")
        print(f"Hex:          {hex(self.num)}")
        print(f"Binary:       {bin(self.num)}")
        print("--------------------------------------------------")
        print(f"Decimal:      {self.num} (unsigned)")
        print(f"              {sintX(self.num, self.bits)} (signed)")
        print(f"Bits:         {self.bits}")
        print(f"Min signed:   {hex(self.nrange['min_signed'])} ({self.nrange['min_signed']})")
        print(f"Max signed:   {hex(self.nrange['max_signed'])} ({self.nrange['max_signed']})")
        print(f"Max unsigned: {hex(self.nrange['max_unsigned'])} ({self.nrange['max_unsigned']})")

        if self.ntype == "hex":
            print("--------------------------------------------------")
            if self.bits == 32:
                print(f"Float:        {self.h2float(self.n, self.bits)}")
            elif self.bits == 64:
                print(f"Double:       {self.h2double(self.n, self.bits)}")


class Integer:
    """Utility class for integer conversions"""

    @staticmethod
    def unsigned2signed(unsigned_num: int) -> int:
        """Convert unsigned integer to signed integer"""
        return struct.unpack("i", struct.pack("I", unsigned_num))[0]

    @staticmethod
    def signed2unsigned(signed_num: int) -> int:
        """Convert signed integer to unsigned integer"""
        return struct.unpack("<I", struct.pack("<i", signed_num))[0]
