#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn_utils.lib.convert.type2 import t2str, t2bytes
from pwn_utils.pkg import base92, base100
import base58
import base62
import base64
import base91


default_b64_table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b16encode(text) -> bytes:
    """ bytes -> bytes """
    return base64.b16encode(t2bytes(text))


def b16decode(text) -> bytes:
    """ bytes -> bytes """
    return base64.b16decode(t2bytes(text))


def b32encode(text) -> bytes:
    """ bytes -> bytes """
    return base64.b32encode(t2bytes(text))


def b32decode(text) -> bytes:
    """ bytes -> bytes """
    return base64.b32decode(t2bytes(text))


def b58encode(text) -> bytes:
    """ [bytes, str] -> bytes """
    return base58.b58encode(t2bytes(text))


def b58decode(text) -> bytes:
    """ [bytes, str] -> bytes """
    return base58.b58decode(t2bytes(text))


def b62encode(text) -> bytes:
    """ bytes -> str -> bytes """
    return base62.encodebytes(t2bytes(text)).encode()


def b62decode(text) -> bytes:
    """ str -> bytes """
    return base62.decodebytes(t2str(text))


def b64encode(text, base_table=None) -> bytes:
    """ bytes -> bytes """

    if base_table is None:
        return base64.b64encode(t2bytes(text))
    else:
        return base64.b64encode(t2bytes(text)).translate(bytes.maketrans(default_b64_table, base_table))


def b64decode(text, base_table=None) -> bytes:
    """ bytes -> bytes """

    if base_table is None:
        return base64.b64decode(t2bytes(text))
    else:
        return base64.b64decode(t2bytes(text).translate(bytes.maketrans(base_table, default_b64_table)))


def b64encode_urlsafe(text) -> bytes:
    """ bytes -> bytes """
    return base64.urlsafe_b64encode(t2bytes(text))


def b64decode_urlsafe(text) -> bytes:
    """ bytes -> bytes """
    return base64.urlsafe_b64decode(t2bytes(text))


def b85encode(text) -> bytes:
    """ bytes -> bytes """
    return base64.b85encode(t2bytes(text))


def b85decode(text) -> bytes:
    """ bytes -> bytes """
    return base64.b85decode(t2bytes(text))


def b91encode(text) -> bytes:
    """ bytes -> str -> bytes """
    return base91.encode(t2bytes(text)).encode()


def b91decode(text) -> bytearray:
    """ [bytes, str] -> bytearray """
    return base91.decode(t2str(text))


def b92encode(text) -> bytes:
    """ [bytes, str] -> str -> bytes """
    return base92.encode(t2bytes(text)).encode()


def b92decode(text) -> bytes:
    """ str -> str -> bytes """
    return base92.decode(t2str(text)).encode()


def b100encode(text) -> str:
    """ [bytes, str] -> bytes -> str """
    return base100.encode(t2bytes(text)).decode()


def b100decode(text) -> bytes:
    """ [bytes, str] -> bytes """
    return base100.decode(t2bytes(text))
