#!/usr/bin/env python

from pathlib import Path

from pwn import ELF
from pwnkit.lib.log import plog


def find_str(elf: ELF, string: bytes):
    """
    Find the first occurrence of a string in an ELF file.
    
    Args:
        elf: The ELF object to search in
        string: The bytes string to search for
        
    Returns:
        The address of the string if found, otherwise logs an error
    """
    try:
        return next(elf.search(string))
    except StopIteration:
        plog.error(f"Can't find string: {string} in {Path(elf.path).name}")
        return None


def find_symbol(elf: ELF, sym: str):
    """
    Find a symbol in an ELF file.
    
    Args:
        elf: The ELF object to search in
        sym: The symbol name to look for
        
    Returns:
        The address of the symbol if found, otherwise logs an error
    """
    try:
        return elf.symbols[sym]
    except KeyError:
        plog.error(f"Can't find symbol: {sym} in {Path(elf.path).name}")
        return None
