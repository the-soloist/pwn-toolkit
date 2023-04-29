#!/usr/bin/env python
# -*- coding: utf-8 -*-

import functools
from pwn import log, context


__all__ = [
    "log_level"
]


def log_level(level=None):
    def dector(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            old_log_level = context.log_level
            context.log_level = level
            res = func(*args, **kwargs)
            context.log_level = old_log_level
            return res
        return wrapper
    return dector
