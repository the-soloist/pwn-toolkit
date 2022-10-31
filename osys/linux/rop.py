#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
from typing import Union
from pwn import ELF, ROP
from pwnlib.tubes.tube import tube
from pwnutils import plog


class UsefulGadgets:
    pop_rdi_ret = None
    leave_ret = None
    syscall_ret = None


class Gadgets(ROP):
    def __init__(self, elf=None, libc=None):
        self.elf = elf
        self.libc = libc
        assert self.elf or self.libc

        self.elf_rop = ROP(self.elf) if self.elf else None
        self.libc_rop = ROP(self.libc) if self.libc else None
        self.rop = [self.elf_rop, self.libc_rop]

        self.ug = UsefulGadgets()

        self.init_useful_gadgets()

    def init_useful_gadgets(self):
        pass

    def orw(path="flag", buf=None, size=0x100):
        """
        open
        read
        write
        """
        pass

    def os():
        """
        open()
        sendfile()
        """
        pass

    def shell(func="system", args=["/bin/sh"]):
        pass


def get_one_gadget_list(filename):
    # return list(map(int, subprocess.check_output(['one_gadget', '--raw', filename]).split(b' ')))
    from pwnutils.lib.cache import CmdCache

    cc = CmdCache(
        cmd=['one_gadget', '--raw', "$filename"],
        filename=filename,
        handler=lambda exec_args: list(map(int, subprocess.check_output(exec_args).split(b' '))),
    )

    if cc.search():
        return cc.result
    else:
        cc.run()
        cc.save()
        return cc.result
