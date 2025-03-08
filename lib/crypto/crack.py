#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import itertools
import random
import string
from pwnlib.util.iters import bruteforce, mbruteforce

from pwnkit.lib.log import plog

__all__ = [
    "gen_strings_series",
    "do_hash_pow",
    "do_hash_pow_m",
]


default_string_table = string.ascii_letters + string.digits


def gen_strings_series(s, n=4, method="fixed"):
    """Generate string combinations for brute-force attacks.

    Args:
        s (str/iterable): Character set or iterable to combine
        n (int): Length of generated strings
        method (str): Generation mode:
            - "fixed": Generate all combinations in dictionary order (itertools.product)
            - "random": Generate infinite random combinations (random.sample)

    Yields:
        str: Generated strings of specified length

    Raises:
        ValueError: If invalid generation method is specified
    """
    if method == "fixed":
        for i in itertools.product(s, repeat=n):
            yield "".join(i)
    elif method == "random":
        while True:
            yield "".join(random.sample(s, n))
    raise ValueError(f"Invalid generation method: {method}")


def do_hash_pow(mode: str, target: str, prefixes="", suffixes="", strings=default_string_table, strmethod="fixed", length=4) -> str | None:
    """Perform proof-of-work by finding a string that creates a hash with specific prefix/suffix.

    Args:
        mode (str): Hash algorithm name (must be in hashlib)
        target (str): Target hex digest to match
        prefixes (str): Fixed prefix before the unknown part
        suffixes (str): Fixed suffix after the unknown part
        strings (str): Character set for unknown part (default: a-zA-Z0-9)
        strmethod (str): Generation method:
            - "fixed": Exhaustive search in order
            - "random": Random attempts (may miss solutions)
        length (int): Length of unknown part to find

    Returns:
        str | None: The found unknown part (between prefixes/suffixes) or None

    Example:
        >>> # Find 4-character string where md5("pre"+xxx+"post") matches target
        >>> solution = do_hash_pow("md5", "d3addcbfd4a13264e7d...", 
        ...                        prefixes="pre", suffixes="post", length=4)
    """

    assert mode in dir(hashlib), f"Unsupported hash algorithm: {mode}"

    plog.waitfor(f"Cracking: {mode}(\'{prefixes}\' + \'{'?'*length}\' + \'{suffixes}\') == {target}")

    for i in gen_strings_series(strings, length, method=strmethod):
        content = prefixes + i + suffixes
        obj = hashlib.__get_builtin_constructor(mode)()
        obj.update(content.encode())

        if obj.hexdigest() == target:
            plog.success(f"Found {mode}({content}) == {target}")
            return i

    plog.failure("No solution found")
    return None


def do_hash_pow_m(mode: str, target: str, prefixes="", suffixes="", strings=default_string_table, strmethod="upto", length=6, threads=16) -> str | None:
    """Multi-threaded version of do_hash_pow using pwnlib's mbruteforce.

    Args:
        mode (str): Hash algorithm name (must be in hashlib)
        target (str): Target hex digest to match
        prefixes (str): Fixed prefix before the unknown part
        suffixes (str): Fixed suffix after the unknown part  
        strings (str): Character set for unknown part
        strmethod (str): mbruteforce generation method:
            - "fixed": Exact length (default)
            - "upto": Try lengths from 1 up to 'length'
            - "downfrom": Try from 'length' down to 1
        length (int): Maximum length for unknown part
        threads (int): Number of worker threads to use

    Returns:
        str | None: The found unknown part or None

    Example:
        >>> # Find string up to 8 chars using 16 threads
        >>> solution = do_hash_pow_m("sha256", "aec7f1...", 
        ...                          prefixes="start", length=8, threads=16)
    """

    assert mode in dir(hashlib), f"Unsupported hash algorithm: {mode}"

    plog.waitfor(f"Cracking: {mode}(\'{prefixes}\' + \'{'?'*length}\' + \'{suffixes}\') == {target}")

    def brute(cur: str) -> bool:
        content = prefixes + cur + suffixes  # cur is already a string
        obj = hashlib.__get_builtin_constructor(mode)()
        obj.update(content.encode())
        return obj.hexdigest() == target

    res = mbruteforce(brute, strings, method=strmethod, length=length, threads=threads)

    if res:
        plog.success(f"Found {mode}({prefixes}{res}{suffixes}) == {target}")
    else:
        plog.failure("No solution found")
    return res
