#!/usr/bin/env python
# -*- coding: utf-8 -*-

import functools
from pwn import ELF, ROP, asm
from typing import Union

from pwnkit.lib.system.linux import search_gadget

__all__ = [
    "GadgetBox",
    "search_gadget",
]


def _search_method(func):
    @functools.wraps(func)
    def wrapper(self, target: Union[str, bytes, list], raw=False, index=-1, **k):
        gen = func(self, target, **k)

        if raw:
            return list(gen)

        if index > -1:
            for _ in range(index):
                next(gen)
            return next(gen)

        return gen
    return wrapper


class GadgetBox(object):
    def __init__(self, elf: Union[str, ELF], text_base=0):
        self.elf = elf if isinstance(elf, ELF) else ELF(elf)
        self.text_base = text_base

    @_search_method
    def search_string(self, target: bytes, writable=False, executable=False):
        for offset in self.elf.search(target, writable, executable):
            yield self.text_base + offset

    @_search_method
    def search_gadget(self, target: list, writable=False, executable=True):
        for offset in search_gadget(self.elf, target, writable, executable):
            yield self.text_base + offset

    @_search_method
    def search_opcode(self, target: bytes, writable=False, executable=True):
        for offset in self.elf.search(target, writable, executable):
            yield self.text_base + offset

    def symbols(self, name):
        return self.text_base + self.elf.symbols[name]
