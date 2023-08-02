#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import ELF, asm
from pwnutils.core.log import ulog
from pwnutils.core.decorates import log_level


@log_level("info")
def search_gadget(elf: ELF, instructions: list, writable=False, executable=True):
    inst = "\n".join(instructions)

    ulog.info("assembling: \n" + inst)

    return elf.search(asm(inst, arch=elf.arch, os=elf.os, bits=elf.bits), writable, executable)
