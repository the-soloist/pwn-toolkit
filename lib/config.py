#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
import argparse

PT_PATH = Path(__file__).parent.parent


def init_parser() -> argparse.ArgumentParser:
    # init parser
    parser = argparse.ArgumentParser()
    # parser.add_argument("-a", "--argument", action="store")  # for test

    # init group
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--debug", action="store_true")
    group.add_argument("-l", "--local", action="store_true")
    group.add_argument("-r", "--remote", action="store_true")

    # init awd sub parser
    subparsers = parser.add_subparsers(help='sub command')
    awd_parsers = subparsers.add_parser('awd', help='awd help')
    awd_parsers.add_argument('-tl', "--target_list", action="store", default=None, help='add target list')

    return parser
