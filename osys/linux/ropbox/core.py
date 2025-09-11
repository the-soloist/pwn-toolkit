#!/usr/bin/env python

import functools
from collections.abc import Generator
from typing import List, Union

from pwn import ELF
from pwnkit.core.log import ulog
from pwnkit.lib.system.linux import search_gadget

__all__ = [
    "GadgetBox",
    "search_gadget",
]


def _search_method(func):
    """Decorator for search methods to handle raw results or indexing."""
    @functools.wraps(func)
    def wrapper(self, target: Union[str, bytes, List[str]], raw: bool = False, index: int = -1, **kwargs):
        gen = func(self, target, **kwargs)

        if raw:
            return list(gen)

        if index > -1:
            for _ in range(index):
                next(gen)
            return next(gen)

        return gen
    return wrapper


class GadgetBox:
    """Utility class for searching gadgets, strings, and opcodes in ELF files."""

    def __init__(self, elf: Union[str, ELF], text_base: int = 0):
        """
        Initialize a GadgetBox for ROP gadget searching.

        Args:
            elf: Path to ELF file or ELF object
            text_base: Base address for text section (for PIE binaries)
        """
        self.elf = elf if isinstance(elf, ELF) else ELF(elf)
        self.text_base = text_base

    @_search_method
    def search_string(self, target: bytes, writable: bool = False,
                      executable: bool = False) -> Generator[int, None, None]:
        """Search for string patterns in the binary."""
        for offset in self.elf.search(target, writable=writable, executable=executable):
            yield self.text_base + offset

    @_search_method
    def search_gadget(self, target: List[str], writable: bool = False, executable: bool = True) -> Generator[int, None, None]:
        """Search for assembly gadgets in the binary."""
        for offset in search_gadget(self.elf, target, writable=writable, executable=executable):
            yield self.text_base + offset

    @_search_method
    def search_opcode(self, target: bytes, writable: bool = False, executable: bool = True) -> Generator[int, None, None]:
        """Search for raw opcodes in the binary."""
        for offset in self.elf.search(target, writable=writable, executable=executable):
            yield self.text_base + offset

    def symbols(self, name: str) -> int:
        """Get the address of a symbol with text_base applied."""
        try:
            return self.text_base + self.elf.symbols[name]
        except KeyError:
            ulog.warning(f"Symbol '{name}' not found in binary")
            return 0
