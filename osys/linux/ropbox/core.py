#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import ELF, ROP, asm
from pwnutils.lib.system.linux import search_gadget
from typing import Union

__all__ = [
    "GadgetBox",
    "search_gadget",
]


class GadgetBox(object):
    def __init__(self, elf: Union[str, ELF]):
        self.elf = elf if isinstance(elf, ELF) else ELF(elf)

    def search_string(self, string: str, writable=False, executable=False):
        return self.elf.search(string.encode(), writable, executable)

    def search_gadget(self, gadget: list, writable=False, executable=True):
        return search_gadget(self.elf, gadget, writable, executable)

    def search_opcode(self, opcode: bytes, writable=False, executable=True):
        return self.elf.search(opcode, writable, executable)
