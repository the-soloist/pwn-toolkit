#!/usr/bin/env python
# -*- coding: utf-8 -*-

import psutil
import sys
from pathlib import Path
from psutil._common import bytes2human
from psutil._compat import get_terminal_size
from pwnkit.lib.log import plog
from pwn import gdb, log, process


def safe_print(s):
    """Print string safely, truncating to terminal width and handling encoding issues."""
    s = s[: get_terminal_size()[0]]
    try:
        print(s)
    except UnicodeEncodeError:
        print(s.encode("ascii", "ignore").decode())


def get_base(libs=None, elf=None, p=None):
    """
    Get base addresses for text and libc sections.
    
    Usage:
        text_base, libc_base = get_base(libs=p.libs(), elf=elf)
        text_base, libc_base = get_base(p=p)
    
    Returns:
        tuple: (text_base_address, libc_base_address)
    """
    if not libs and p:
        return get_text_base(p)
    
    if not libs or not elf:
        plog.warning("get_base: requires either (libs and elf) or sh")
        return None, None

    try:
        text_base = libs[elf.path]
    except KeyError:
        plog.warning("get_base: couldn't find elf path in libs")
        return None, None

    # Find libc base address
    for key in libs:
        if "libc" in key:
            return text_base, libs[key]
    
    return text_base, None


def get_text_base(sh: process):
    """
    Get text and libc base addresses from a process.
    
    Args:
        sh: process object
        
    Returns:
        tuple: (text_base_address, libc_base_address)
    """
    libs = sh.libs()
    
    try:
        if sys.version_info.major >= 3:
            text_base = libs[str(sh.argv[0].strip(b"."), encoding="utf-8")]
        else:
            text_base = libs[str(sh.argv[0].strip("."))]
    except (KeyError, IndexError):
        plog.warning("get_text_base: couldn't determine text base address")
        return None, None

    # Find libc base address
    for key in libs:
        if "libc" in key:
            return text_base, libs[key]
    
    return text_base, None


def get_core_maps(proc: process):
    """Get memory mappings from a core file."""
    return proc.corefile.mappings


def get_vmmap(proc: process):
    """Get virtual memory mappings for a process."""
    return get_all_maps(proc)


def get_heap_map(proc: process):
    """
    Get heap memory mapping for a process.
    
    Args:
        proc: process object
        
    Returns:
        Memory map object or None if heap not found
    """
    p = psutil.Process(proc.pid)
    templ = "%-20s %10s  %-7s %s"
    
    try:
        memory_maps = p.memory_maps(grouped=False)
        for m in memory_maps:
            if m.path == "[heap]":
                safe_print(templ % (m.addr.split("-")[0].zfill(16), bytes2human(m.rss), m.perms, m.path))
                return m
    except psutil.AccessDenied:
        plog.warning("get_heap_map: access denied")
        return None
    except psutil.NoSuchProcess:
        plog.warning("get_heap_map: process no longer exists")
        return None

    plog.warning("get_heap_map: can't find heap address")
    return None


def get_all_maps(proc: process):
    """
    Get all memory mappings for a process.
    
    Args:
        proc: process object
        
    Returns:
        List of memory map objects
    """
    try:
        p = psutil.Process(proc.pid)
        return p.memory_maps(grouped=False)
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        plog.warning("get_all_maps: couldn't access process memory maps")
        return []


def print_all_map(proc: process):
    """
    Print all memory mappings for a process.
    
    Args:
        proc: process object
        
    Returns:
        List of memory map objects
    """
    try:
        p = psutil.Process(proc.pid)
        templ = "%-20s %10s  %-7s %s"
        print(templ % ("Address", "RSS", "Mode", "Mapping"))
        
        total_rss = 0
        mem_maps = p.memory_maps(grouped=False)
        
        for m in mem_maps:
            total_rss += m.rss
            safe_print(templ % (m.addr.split("-")[0].zfill(16), bytes2human(m.rss), m.perms, m.path))
        
        print("-" * 31)
        print(templ % ("Total", bytes2human(total_rss), "", ""))
        safe_print(f"PID = {p.pid}, name = {p.name()}")
        
        return mem_maps
    except psutil.AccessDenied:
        plog.warning("print_all_map: access denied")
        return []
    except psutil.NoSuchProcess:
        plog.warning("print_all_map: process no longer exists")
        return []
