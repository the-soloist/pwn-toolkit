#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwnlib.constants.linux import amd64 as constants


""" 64 bits """


def read(fd, buf, count):
    # ssize_t read(int fd, void *buf, size_t count);

    code = [
        f"mov rdi, {fd}",
        f"mov rsi, {buf}",
        f"mov rdx, {count}",
        f"mov rax, {int(constants.__NR_read)}",
        "syscall"
    ]

    return "\n".join(code)


def write(fd, buf, count):
    # ssize_t write(int fd, void *buf, size_t count);

    code = [
        f"mov rdi, {fd}",
        f"mov rsi, {buf}",
        f"mov rdx, {count}",
        f"mov rax, {int(constants.__NR_read)}",
        "syscall"
    ]

    return "\n".join(code)


def open(pathname, flags, mode=0):
    # int open(const char *pathname, int flags, mode_t mode);

    code = [
        f"mov rdi, {pathname}",
        f"mov rsi, {flags}",
        f"mov rdx, {mode}",
        f"mov rax, {int(constants.__NR_open)}",
        "syscall"
    ]

    return "\n".join(code)


def mmap(start, length, prot, flags, fd, offsize):
    # void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offsize);

    code = [
        f"mov rdi, {start}",
        f"mov rsi, {length}",
        f"mov rdx, {prot}",
        f"mov r10, {flags}",
        f"mov r8, {fd}",
        f"mov r9, {offsize}",
        f"mov rax, {int(constants.__NR_mmap)}",
        "syscall"
    ]

    return "\n".join(code)


def call(syscall_name, rdi=None, rsi=None, rdx=None, r10=None, r8=None, r9=None):
    nr = getattr(constants, f"__NR_{syscall_name}")

    code = ""
    if rdi:
        code += f"mov rdi, {start}\n"
    if rsi:
        code += f"mov rsi, {length}\n"
    if rdx:
        code += f"mov rdx, {prot}\n"
    if r10:
        code += f"mov r10, {flags}\n"
    if r8:
        code += f"mov r8, {fd}\n"
    if r9:
        code += f"mov r9, {offsize}\n"
    code += f"mov rax, {int(nr)}\n"
    code += "syscall"

    return "\n".join(code)


""" 32 bits  """


def sys32_open(pathname, flags, mode=0):
    # int open(const char *pathname, int flags, mode_t mode);

    code = [
        f"mov rbx, {pathname}",
        f"mov rcx, {flags}",
        f"mov rdx, {mode}",
        f"mov rax, {int(constants.SYS32_open)}",
        "int 0x80"
    ]

    return "\n".join(code)


def sys32_mmap(start, length, prot, flags, fd, offsize):
    # void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offsize);

    code = [
        f"mov rbx, {start}",
        f"mov rcx, {length}",
        f"mov rdx, {prot}",
        f"mov rsi, {flags}",
        f"mov rdi, {fd}",
        f"mov rbp, {offsize}",
        f"mov rax, {int(constants.SYS32_mmap)}",
        "int 0x80"
    ]

    return "\n".join(code)


def sys32_mmap2(start, length, prot, flags, fd, offsize):
    # void *mmap2(void *start, size_t length, int prot, int flags, int fd, off_t offsize);

    code = [
        f"mov rbx, {start}",
        f"mov rcx, {length}",
        f"mov rdx, {prot}",
        f"mov rsi, {flags}",
        f"mov rdi, {fd}",
        f"mov rbp, {offsize}",
        f"mov rax, {int(constants.SYS32_mmap2)}",
        "int 0x80"
    ]

    return "\n".join(code)


def sys32_getdents(fd, dirp, count):
    # int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

    code = [
        f"mov rbx, {fd}",
        f"mov rcx, {dirp}",
        f"mov rdx, {count}",
        f"mov rax, {int(constants.SYS32_getdents)}",
        "int 0x80"
    ]

    return "\n".join(code)


def sys32_call(syscall_name, rbx=None, rcx=None, rdx=None, rsi=None, rdi=None, rbp=None):
    nr = getattr(constants, f"SYS32_{syscall_name}")

    code = ""
    if rbx:
        code += f"mov rbx, {start}\n"
    if rcx:
        code += f"mov rcx, {length}\n"
    if rdx:
        code += f"mov rdx, {prot}\n"
    if rsi:
        code += f"mov rsi, {flags}\n"
    if rdi:
        code += f"mov rdi, {fd}\n"
    if rbp:
        code += f"mov rbp, {offsize}\n"
    code += f"mov rax, {int(nr)}\n"
    code += "int 0x80"

    return "\n".join(code)
