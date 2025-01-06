#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from pwn import u8, u16, u32, u64


__all__ = [
    "uu8", "uu16", "uu32", "uu64",
]


uu8 = u8
uu16 = lambda data: u16(data.ljust(2, b"\x00"))
uu32 = lambda data: u32(data.ljust(4, b"\x00"))
uu64 = lambda data: u64(data.ljust(8, b"\x00"))
