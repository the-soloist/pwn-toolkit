#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from argparse import Namespace
from pwn import process, remote, gdb, log
from typing import Union

from pwnkit.core.log import ulog


__all__ = [
    "pwntube",
]


def _validate_env(args: Namespace):
    assert hasattr(args.env, "cmd"), "Missing args.env.cmd"
    assert hasattr(args.env, "kwargs"), "Missing args.env.kwargs"


def _get_command(args: Namespace, default_cmd):
    assert isinstance(args.env.cmd, list)
    if len(args.env.cmd) > 0:
        return args.env.cmd
    return [default_cmd]


def _get_command(args: Namespace, default_cmd: Union[str, list]) -> list:
    """Get command list from args or use default command"""
    assert isinstance(args.env.cmd, list), "args.env.cmd must be a list"
    return args.env.cmd if args.env.cmd else [default_cmd]


def _delete_unexpected_keyword(arg: dict, klist: list[str]) -> None:
    """Safely remove unexpected keys from a dictionary"""
    for k in klist:
        arg.pop(k, None)


def pwntube(args: Namespace, force=None):
    """
    Arguments:
        force(str):
            force run in choosen mode
        upload(boolen):
            auto upload files in SSH mode
    """

    if force:
        """ io = pwntube(args, force="remote") """
        log.info(f"set {force} mode")
        setattr(args, force, True)

    # set log level
    if args.verbose:
        log_levels = {
            1: "INFO",
            2: "DEBUG",
            3: "TRACE"
        }
        ulog.level(log_levels.get(args.verbose, "ERROR"))

    # remote mode
    if args.remote:
        """ args.info.target = {"host": "example.server", "port": 9999} """
        io = remote(**args.info.target)
        io._process_mode = "remote"

    # websocket mode
    elif args.websocket:
        """ args.info.target = {"url": "wss://example.server"} """
        from pwnkit.lib.tubes import websocket

        io = websocket(**args.info.target)
        io._process_mode = "websocket"

    # ssh mode
    elif args.ssh:
        from pwnlib.tubes.ssh import ssh as SSH

        _validate_env(args)
        assert isinstance(args.env.ssh, SSH)

        command = _get_command(args, os.path.basename(args.info.binary.path))

        io = args.env.ssh.process(command, **args.env.kwargs)
        io._process_mode = "ssh"

    # local mode
    elif args.local:
        """
        Run with local mode:

          >>> io = process([ld.path, binary.path], env={"LD_PRELOAD": libc.path})
          >>> io = process([f"qemu-{context.arch}", "-g", "9999", "-L", ".", binary.path])

          >>> args.env.cmd = [ld.path, binary.path]
          >>> args.env.kwargs = { "env": {"LD_PRELOAD": "/path/to/libc.so"}, }

        Start with qemu:
        1. append gdb script:
            ```
            GDB_SCRIPT += "file /path/to/binary"
            GDB_SCRIPT += "target remote :9999"
            ```

        2. edit py script:
            ```
            from pwnkit.osys.linux.elf.process import kill_process_by_name
            kill_process_by_name("qemu")
            ```

          >>> args.env.cmd = [f"qemu-{context.arch}", "-g", "9999", "-L", ".", binary.path]
          >>> args.env.cmd = ["./run.sh"]

          >>> cat ./run.sh
          #!/bin/bash
          qemu-mips -g 9999 -L . /path/to/binary
        """

        _validate_env(args)

        command = _get_command(args, args.info.binary.path)

        _delete_unexpected_keyword(args.env.kwargs, ["gdbscript"])

        io = process(command, **args.env.kwargs)
        io._process_mode = "local"

    # debug mode
    elif args.debug:
        """ 
        Run with debug mode:

          >>> args.env.kwargs = {"gdbscript": GDB_SCRIPT, }

          >>> # debug with qemu
          >>> context.os = "baremetal"  # qemu-system
          >>> args.env.kwargs = {"gdbscript": GDB_SCRIPT, "sysroot": "/path/to/sysroot"}
          >>> args.env.kwargs = {"gdbscript": GDB_SCRIPT, "env": {b"QEMU_LD_PREFIX": "."}}
        """

        assert hasattr(args.env, "cmd")
        assert hasattr(args.env, "kwargs")

        command = _get_command(args, args.info.binary.path)

        io = gdb.debug(command, **args.env.kwargs)
        io._process_mode = "debug"

    else:
        from pwnkit import parser

        parser.print_help()
        exit(0)

    return io
