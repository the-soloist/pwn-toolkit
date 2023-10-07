#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base45
import base58
import base62
import base64
import base91
import pybase100 as base100
import inspect

from typing import Union

from pwnkit.lib.convert.type2 import v2s, v2b
from pwnkit.pkg import base92

default_table = {
    "b16": b"0123456789ABCDEF",
    "b32": b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    "b45": b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+\-./:",
    "b58": b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
    "b64": b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
}


def b16encode(text: Union[bytes, str]) -> bytes:
    """ bytes -> bytes """
    return base64.b16encode(v2b(text))


def b16decode(text: Union[bytes, str]) -> bytes:
    """ bytes -> bytes """
    return base64.b16decode(v2b(text))


def b32encode(text: Union[bytes, str]) -> bytes:
    """ bytes -> bytes """
    return base64.b32encode(v2b(text))


def b32decode(text: Union[bytes, str]) -> bytes:
    """ bytes -> bytes """
    return base64.b32decode(v2b(text))


def b45encode(text: Union[bytes, str]) -> bytes:
    """ bytes -> bytes """
    return base45.b45encode(v2b(text))


def b45decode(text: Union[bytes, str]) -> bytes:
    """ bytes -> bytes """
    return base45.b45decode(v2b(text))


def b58encode(text: Union[bytes, str]) -> bytes:
    """ [bytes, str] -> bytes """
    return base58.b58encode(text)


def b58decode(text: Union[bytes, str]) -> bytes:
    """ [bytes, str] -> bytes """
    return base58.b58decode(text)


def b62encode(text: Union[bytes, str]) -> bytes:
    """ bytes -> str -> bytes """
    return base62.encodebytes(v2b(text)).encode()


def b62decode(text: Union[bytes, str]) -> bytes:
    """ str -> bytes """
    return base62.decodebytes(v2s(text))


def b64encode(text: Union[bytes, str]) -> bytes:
    """ bytes -> bytes """
    return base64.b64encode(v2b(text))


def b64decode(text: Union[bytes, str]) -> bytes:
    """ bytes -> bytes """
    return base64.b64decode(v2b(text))


def b64encode_urlsafe(text) -> bytes:
    """ bytes -> bytes """
    return base64.urlsafe_b64encode(v2b(text))


def b64decode_urlsafe(text) -> bytes:
    """ bytes -> bytes """
    return base64.urlsafe_b64decode(v2b(text))


def b85encode(text: Union[bytes, str]) -> bytes:
    """ bytes -> bytes """
    return base64.b85encode(v2b(text))


def b85decode(text: Union[bytes, str]) -> bytes:
    """ bytes -> bytes """
    return base64.b85decode(v2b(text))


def b91encode(text: Union[bytes, str]) -> bytes:
    """ bytes -> str -> bytes """
    return base91.encode(v2b(text)).encode()


def b91decode(text: Union[bytes, str]) -> bytearray:
    """ [bytes, str] -> bytearray """
    return base91.decode(text)


def b92encode(text: Union[bytes, str]) -> bytes:
    """ [bytes, str] -> str -> bytes """
    return base92.b92encode(text).encode()


def b92decode(text: Union[bytes, str]) -> bytes:
    """ str -> str -> bytes """
    return base92.b92decode(v2s(text)).encode()


def b100encode(text: Union[bytes, str]) -> str:
    """ [bytes, str] -> bytes -> str """
    return base100.encode(text).decode()


def b100decode(text: Union[bytes, str]) -> bytes:
    """ [bytes, str] -> bytes """
    return base100.decode(text)


def encode(base: int, text: Union[bytes, str]):
    from pwnkit.lib.encode import base as base_functions

    encode_func = getattr(base_functions, f"b{base}encode")

    return encode_func(v2b(text))


def decode(text: Union[bytes, str]):
    from pwnkit.lib.encode import base as base_functions

    decode_func = getattr(base_functions, f"b{base}decode")

    return decode_func(v2b(text))


def trans_encode(base: int, text: Union[bytes, str], table):
    from pwnkit.lib.encode import base as base_functions

    encode_func = getattr(base_functions, f"b{base}encode")

    return encode_func(v2b(text)).translate(bytes.maketrans(default_table[f"b{base}"], table))


def trans_decode(text: Union[bytes, str], table):
    from pwnkit.lib.encode import base as base_functions

    decode_func = getattr(base_functions, f"b{base}decode")

    return decode_func(v2b(text).translate(bytes.maketrans(table, default_table[f"b{base}"])))
