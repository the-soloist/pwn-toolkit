#!/usr/bin/env python
# -*- coding: utf-8 -*-

from psutil._common import bytes2human
from psutil._compat import get_terminal_size
from pwn import gdb, log
import psutil
import sys


def safe_print(s):
    s = s[: get_terminal_size()[0]]
    try:
        print(s)
    except UnicodeEncodeError:
        print(s.encode("ascii", "ignore").decode())


def get_base(libs=None, elf=None, sh=None):
    """ Usage:
    text_base, libc_base = get_base(libs=sh.libs(), elf=elf)
    text_base, libc_base = get_base(sh=sh)

    if sys.version_info.major < 3:
        text_base = libs[str(args.elf.path)]
        # text_base = libs[str(sh.argv[0].strip("."))]
    """

    if (not libs and not elf) or (not sh):
        log.warn("get_base: set sh / libs and elf")

    if elf is None:
        return get_sh_base(sh)

    try:
        _text_base = libs[elf.path]
        # _text_base = libs[str(sh.argv[0].strip(b"."), encoding="utf-8")]
    except:
        print(libs)
        log.warn("get_base: try it again!")

    for key in libs:
        if "libc" in key:
            return _text_base, libs[key]


def get_sh_base(sh):
    libs = sh.libs()

    if sys.version_info.major >= 3:
        _text_base = libs[str(sh.argv[0].strip(b"."), encoding="utf-8")]
    else:
        _text_base = libs[str(sh.argv[0].strip("."))]

    for key in libs:
        if "libc" in key:
            return _text_base, libs[key]


def get_core_maps(sh):
    # print(sh.corefile.maps)
    return sh.corefile.mappings


def get_heap_map(sh):
    p = psutil.Process(sh.pid)
    templ = "%-20s %10s  %-7s %s"
    M = p.memory_maps(grouped=False)
    for idx in range(len(M)):
        m = p.memory_maps(grouped=False)[idx]
        if m.path == "[heap]":
            safe_print(templ % (m.addr.split("-")[0].zfill(16), bytes2human(m.rss), m.perms, m.path))
            return m

    log.warn("get_heap_map: can't find heap address.")
    return None


def print_all_map(sh):
    p = psutil.Process(sh.pid)
    templ = "%-20s %10s  %-7s %s"
    print(templ % ("Address", "RSS", "Mode", "Mapping"))
    total_rss = 0
    mem_maps = p.memory_maps(grouped=False)
    for m in mem_maps:
        total_rss += m.rss
        safe_print(templ % (m.addr.split("-")[0].zfill(16), bytes2human(m.rss), m.perms, m.path))
    print("-" * 31)
    print(templ % ("Total", bytes2human(total_rss), "", ""))
    safe_print("PID = %s, name = %s" % (p.pid, p.name()))
    return mem_maps
