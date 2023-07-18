#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pathlib import Path


def mkdir_s(path: Path):
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)


def touch_s(path: Path):
    mkdir_s(path.parent)
    path.touch()
