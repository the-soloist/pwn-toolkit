#!/usr/bin/env python3
import argparse
import configparser
import os
from pathlib import Path

from pwnkit.core.classes import ArgInfo, ArgEnv

__all__ = [
    "PU_HOME",
    "SETTING",
    "init_pwn_args",
    "init_parser",
]


PU_HOME = Path(__file__).parent.parent
SETTING = configparser.ConfigParser()
SETTING.read(PU_HOME / "setting.ini")


def config_context_terminal():
    from pwn import context, log

    # Skip if terminal already configured
    if context.terminal:
        log.debug(f"context.terminal already set to: {context.terminal}")
        return

    # Set `context.terminal`
    if os.getenv("TMUX"):
        split_horizon = os.get_terminal_size().columns - 89
        context.terminal = ["tmux", "sp", "-h", "-l", str(split_horizon)]
        log.debug(f"Set context.terminal for tmux: {context.terminal}")


def init_pwn_args(parser=None):
    if not parser:
        parser = init_parser()

    args = parser.parse_args()
    args.force = None
    args.info = ArgInfo()
    args.env = ArgEnv()

    config_context_terminal()  # Fix typo in function name

    if not args.debug and not args.local and not args.remote and not args.ssh and not args.websocket:
        parser.print_help()
        exit(1)

    return args


def init_parser() -> argparse.ArgumentParser:
    # init parser
    parser = argparse.ArgumentParser()
    # parser.add_argument("-a", "--argument", action="store")  # for test

    # init mutually exclusive group
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-d", "--debug", action="store_true")
    group.add_argument("-l", "--local", action="store_true")
    group.add_argument("-r", "--remote", action="store_true")
    group.add_argument("-s", "--ssh", action="store_true")
    group.add_argument("-w", "--websocket", action="store_true")

    # init default parser
    parser.add_argument("-v", "--verbose", action="count", help="print verbose output")
    parser.add_argument("--host", action="store", default=None, type=str)
    parser.add_argument("--url", action="store", default=None, type=str)
    parser.add_argument("--port", action="store", default=0, type=int)

    # init awd sub parser
    subparsers = parser.add_subparsers(dest="subparser", help="sub command")
    awd_parsers = subparsers.add_parser("awd", help="awd help")
    awd_parsers.add_argument("-tl", "--target_list", action="store", default=None, help="add target list")
    awd_parsers.add_argument("-st", "--sleep_time", action="store", type=int, default=-1, help="set sleep time")

    return parser
