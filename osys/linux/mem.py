#!/usr/bin/env python

import math

from pwnkit.lib.convert.type2 import b2i, v2b


def bytes2mem(string, mode=64, endian="little"):
    """ Usage:

    bytes2mem("/path/to/flag", 64, "little") -> [0x6f742f687461702f, 0x67616c662f]
    """
    assert mode % 8 == 0, "Mode must be a multiple of 8"
    bytes_align = mode // 8
    string = v2b(string)

    # Calculate exact number of chunks needed
    chunks = math.ceil(len(string) / bytes_align)

    # Use list comprehension for better performance
    return [b2i(string[i * bytes_align:(i + 1) * bytes_align], endian)
            for i in range(chunks)]
