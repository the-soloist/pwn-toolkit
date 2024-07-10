#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import ELF, asm, context

from pwnkit.core.decorates import log_level
from pwnkit.core.log import ulog


@log_level("info")
def search_gadget(elf: ELF, instructions: list, writable=False, executable=True):
    inst = "\n".join(instructions)

    ulog.info("assembling: \n" + inst)
    return elf.search(asm(inst, arch=elf.arch, os=elf.os, bits=elf.bits), writable, executable)
