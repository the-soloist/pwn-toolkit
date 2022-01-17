#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64


default_b64_table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64encode(text: bytes, b64table=default_b64_table):
    return base64.b64encode(text).translate(bytes.maketrans(default_b64_table, b64table))


def b64decode(text: bytes, b64table=default_b64_table):
    return base64.b64decode(text.translate(bytes.maketrans(b64table, default_b64_table)))
