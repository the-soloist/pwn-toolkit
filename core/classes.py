#!/usr/bin/env python
# -*- coding: utf-8 -*-

__all__ = [
    "ArgInfo", "ArgCLI",
    "EmptyClass",
]


class EmptyClass(object):
    pass


class ArgInfo(object):
    binary = None
    target = ()


class ArgCLI(object):
    ssh = None
    cmd = []
    kwargs = {}
