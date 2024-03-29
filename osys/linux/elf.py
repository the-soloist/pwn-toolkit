#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import ELF
from pathlib import Path

from pwnkit.lib.log import plog


def find_str(elf: ELF, string: bytes):
    try:
        return next(elf.search(string))
    except:
        plog.error(f"Can't find string: {string} in {Path(elf.path).name}")


def find_symbol(elf: ELF, sym: str):
    try:
        return elf.symbols[sym]
    except:
        plog.error(f"Can't find symbol: {sym} in {Path(elf.path).name}")
