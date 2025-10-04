#!/usr/bin/env python

from collections.abc import Generator
from typing import List

from pwn import ELF, asm
from pwnkit.core.decorates import with_log_level
from pwnkit.core.log import ulog


@with_log_level("info")
def search_gadget(elf: ELF, instructions: List[str], writable: bool = False, executable: bool = True) -> Generator[int, None, None]:
    """
    Search for a gadget in the ELF file.

    Args:
        elf: The ELF object to search in
        instructions: List of assembly instructions to search for
        writable: Whether to search in writable sections
        executable: Whether to search in executable sections

    Returns:
        Generator yielding addresses where the gadget is found
    """
    inst = "\n".join(instructions)
    ulog.info(f"Searching for gadget:\n{inst}")

    try:
        gadget_bytes = asm(inst, arch=elf.arch, os=elf.os, bits=elf.bits)
        return elf.search(
            gadget_bytes,
            writable=writable,
            executable=executable
        )
    except Exception as e:
        ulog.error(f"Failed to assemble gadget: {e}\n{inst}")
