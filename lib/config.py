#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import configparser
from pathlib import Path


__all__ = [
    "PU_HOME",
    "SETTING",
    "init_parser",
]


PU_HOME = Path(__file__).parent.parent
SETTING = configparser.ConfigParser()
SETTING.read(PU_HOME / "setting.ini")


def init_parser() -> argparse.ArgumentParser:
    # init parser
    parser = argparse.ArgumentParser()
    # parser.add_argument("-a", "--argument", action="store")  # for test

    # init mutually exclusive group
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--debug", action="store_true")
    group.add_argument("-l", "--local", action="store_true")
    group.add_argument("-r", "--remote", action="store_true")
    group.add_argument("-w", "--websocket", action="store_true")

    # init default parser
    parser.add_argument("-v", "--verbose", action="count", help="print verbose output")

    # init awd sub parser
    subparsers = parser.add_subparsers(help="sub command")
    awd_parsers = subparsers.add_parser("awd", help="awd help")
    awd_parsers.add_argument("-tl", "--target_list", action="store", default=None, help="add target list")

    return parser
