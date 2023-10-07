#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib

from pwnkit.lib.convert.type2 import v2b


CRLF = b"\r\n"

# alias
urldecode = urllib.parse.unquote
urlencode = urllib.parse.quote


def urlencode2bytes(s) -> bytes:
    res = b""
    for c in s:
        res += bytes("%{:02x}".format(c), encoding="utf-8")
    return res


def dump_http_request(method, url, header: dict, data=None) -> bytes:
    dump = bytes(f"{method} {url}", encoding="utf-8") + CRLF

    for k, v in header.items():
        nk, nv = v2b(k), v2b(v)
        dump += nk + b": " + nv + CRLF

    dump += CRLF

    if data:
        dump += v2b(data)

    return dump
