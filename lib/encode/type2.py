#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwnlib.exception import PwnlibException
from typing import Union


def t2bytes(value) -> Union[bytes, bytearray]:
    """ convert to bytes """

    if type(value) == str:
        return bytes(value, encoding="utf-8")
    elif type(value) == bytes or type(value) == bytearray:
        return value
    else:
        raise PwnlibException("unsupport type")
