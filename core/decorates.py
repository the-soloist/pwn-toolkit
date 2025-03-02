#!/usr/bin/env python
# -*- coding: utf-8 -*-

import functools
from pwn import log, context

from pwnkit.core.log import ulog

__all__ = [
    "with_log_level",
    "use_pwnio",
]


def with_log_level(level):
    """
    Temporarily modify context.log_level decorator.

    Args:
        level: The log level to set during function execution

    Returns:
        Decorated function with temporarily modified log level
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Log at debug level only when actually calling the function
            ulog.debug(f"Temporarily setting log level to '{level}'")

            # Store original level and restore it after execution
            original_level = context.log_level
            context.log_level = level
            try:
                return func(*args, **kwargs)
            finally:
                context.log_level = original_level
        return wrapper
    return decorator


def use_pwnio(func):
    """
    Decorator that automatically passes the pwnobj.io as the first argument to the decorated function.
    
    This allows functions to directly use the current pwn IO object without explicitly importing it.
    
    Args:
        func: The function to be decorated
        
    Returns:
        Wrapped function that receives pwnobj.io as its first argument
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        from pwnkit import pwnobj
        
        ulog.debug(f"Using pwn IO object with function: {func.__name__}")
        return func(pwnobj.io, *args, **kwargs)

    return wrapper
