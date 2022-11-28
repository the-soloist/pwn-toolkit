#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import log, context


__all__ = [
    "force_log_info"
]


def force_log_info(func):
    def wrapper(*args, **kwargs):
        old_log_level = context.log_level
        context.log_level = "info"
        res = func(*args, **kwargs)
        context.log_level = old_log_level
        return res
    return wrapper
