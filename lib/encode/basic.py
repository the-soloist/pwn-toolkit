#!/usr/bin/env python
# -*- coding: utf-8 -*-

from PwnT00ls.lib.convert.type2 import t2str, t2bytes
import html
import urllib


def hex_encode(text):
    """ [bytes, str] -> str """
    return " ".join(['%02X' % x for x in t2bytes(text)])


def hex_decode(text):
    """ [bytes, str] -> bytes """
    hex_list = t2bytes(text).decode().split(" ")
    return b"".join([bytes.fromhex(x) for x in hex_list])


def html_encode(text):
    """ str -> str """
    return html.escape(t2str(text))


def html_decode(text):
    """ str -> str """
    return html.unescape(t2str(text))


def unicode_encode(text):
    """ [bytes, str] -> str """

    res = list()
    for c in t2str(text):
        res.append(f"\\u{char2unicode(c)}")

    return "".join(res)


def unicode_decode(text):
    """ [bytes, str] -> str """
    return t2str(text)


def url_encode(text):
    """ [bytes, str] -> str """
    return urllib.parse.quote(text)


def url_decode(text):
    """ str -> str """
    return urllib.parse.unquote(t2str(text))
