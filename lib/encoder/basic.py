#!/usr/bin/env python

import html
import urllib

from pwnkit.lib.convert.type2 import c2us, v2b, v2s


def hex_encode(text) -> str:
    """ [bytes, str] -> str """
    return " ".join(['%02X' % x for x in v2b(text)])


def hex_decode(text) -> bytes:
    """ [bytes, str] -> bytes """
    hex_list = v2b(text).decode().split(" ")
    return b"".join([bytes.fromhex(x) for x in hex_list])


def html_encode(text) -> str:
    """ str -> str """
    return html.escape(v2s(text))


def html_decode(text) -> str:
    """ str -> str """
    return html.unescape(v2s(text))


def unicode_encode(text) -> str:
    """ [bytes, str] -> str """

    res = list()
    for c in v2s(text):
        res.append(f"\\u{c2us(c)}")

    return "".join(res)


def unicode_decode(text) -> str:
    """ [bytes, str] -> str """
    return v2s(text)


def url_encode(text) -> str:
    """ [bytes, str] -> str """
    return urllib.parse.quote(text)


def url_decode(text) -> str:
    """ str -> str """
    return urllib.parse.unquote(v2s(text))
