#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwnlib.constants.linux import i386 as constants


def mmap(start, length, prot, flags, fd, offsize):
    # void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offsize);

    code = [
        f"mov ebx, {start}",
        f"mov ecx, {length}",
        f"mov edx, {prot}",
        f"mov esi, {flags}",
        f"mov edi, {fd}",
        f"mov ebp, {offsize}",
        f"mov eax, {int(constants.SYS32_mmap)}",
        "int 0x80"
    ]

    return "\n".join(code)


def mmap2(start, length, prot, flags, fd, offsize):
    # void *mmap2(void *start, size_t length, int prot, int flags, int fd, off_t offsize);

    code = [
        f"mov ebx, {start}",
        f"mov ecx, {length}",
        f"mov edx, {prot}",
        f"mov esi, {flags}",
        f"mov edi, {fd}",
        f"mov ebp, {offsize}",
        f"mov eax, {int(constants.SYS32_mmap2)}",
        "int 0x80"
    ]

    return "\n".join(code)


def call(syscall_name, rbx=None, rcx=None, rdx=None, rsi=None, rdi=None, rbp=None):
    nr = getattr(constants, f"__NR_{syscall_name}")

    code = ""
    if rbx:
        code += f"mov ebx, {start}\n"
    if rcx:
        code += f"mov ecx, {length}\n"
    if rdx:
        code += f"mov edx, {prot}\n"
    if rsi:
        code += f"mov esi, {flags}\n"
    if rdi:
        code += f"mov edi, {fd}\n"
    if rbp:
        code += f"mov ebp, {offsize}\n"
    code += f"mov eax, {int(nr)}\n"
    code += "int 0x80"

    return "\n".join(code)
