#!/usr/bin/env python
# -*- coding: utf-8 -*-

from . import convert
from . import crypto
from . import debug
from . import entry
from . import log
from . import system
from . import tubes


def try_import(path, name):
    try:
        exec(f"from {path} import {name}")
    except Exception as e:
        print(f"cannot import lib.{name}, exception: {e}.")


try_import(".", "emu")
try_import(".", "encode")
try_import(".", "http")
del try_import

__all__ = [x for x in globals().keys() if x != "__name__"]
