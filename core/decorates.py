#!/usr/bin/env python
# -*- coding: utf-8 -*-

import functools
from pwn import log, context

from pwnkit.core.log import ulog

__all__ = [
    "log_level",
    "use_pwnio",
]


def log_level(level):
    ulog.debug(f"set pwnlog level to '{level}'")

    def dector(func):
        @functools.wraps(func)
        def wrapper(*a, **k):
            old_log_level = context.log_level
            context.log_level = level
            res = func(*a, **k)
            context.log_level = old_log_level
            return res

        return wrapper

    return dector


def use_pwnio(func):
    ulog.debug("set pwn io")

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        from pwnkit import pwnobj

        return func(pwnobj.io, *args, **kwargs)

    return wrapper
