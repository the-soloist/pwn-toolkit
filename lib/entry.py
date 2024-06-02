#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from pwn import process, remote, gdb, log, pause, context

__all__ = [
    "pwntube"
]


def delete_unexpected_keyword(arg, klist):
    for k in klist:
        try:
            arg.pop(k)
        except:
            pass


def pwntube(args, force=None):
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

    # set context.terminal
    if os.getenv("TMUX"):
        if len(context.terminal) == 0:
            split_horizon = os.get_terminal_size().columns - 89
            context.terminal = ["tmux", "sp", "-h", "-l", str(split_horizon)]
            log.debug(f"set `context.terminal = {str(context.terminal)}`")

    # set log level
    if args.verbose:
        from pwnkit.core.log import ulog

        if args.verbose == 1:
            ulog.level("INFO")
        elif args.verbose == 2:
            ulog.level("DEBUG")
        elif args.verbose >= 3:
            ulog.level("TRACE")

    # remote mode
    if args.remote:
        """ args.info.target = {"host": "example.server", "port": 9999} """
        io = remote(**args.info.target)
        io.process_mode = "remote"

    # websocket mode
    elif args.websocket:
        """ args.info.target = {"url": "wss://example.server"} """
        from pwnkit.lib.tubes import websocket

        io = websocket(**args.info.target)
        io.process_mode = "websocket"

    elif args.ssh:
        from pwnlib.tubes.ssh import ssh as SSH

        assert hasattr(args.env, "cmd")
        assert hasattr(args.env, "kwargs")
        assert isinstance(args.env.ssh, SSH)

        if isinstance(args.env.cmd, list) and len(args.env.cmd) > 0:
            command = args.env.cmd
        else:
            command = [args.info.binary.path]

        io = args.env.ssh.process(command, **args.env.kwargs)
        io.process_mode = "ssh"

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

        assert hasattr(args.env, "cmd")
        assert hasattr(args.env, "kwargs")

        if isinstance(args.env.cmd, list) and len(args.env.cmd) > 0:
            command = args.env.cmd
        else:
            command = [args.info.binary.path.encode()]

        delete_unexpected_keyword(args.env.kwargs, ["gdbscript"])

        io = process(command, **args.env.kwargs)
        io.process_mode = "local"

    # debug mode
    elif args.debug:
        """ 
        Run with debug mode:

          >>> args.env.kwargs = {"gdbscript": GDB_SCRIPT, }
        """

        assert hasattr(args.env, "cmd")
        assert hasattr(args.env, "kwargs")

        if isinstance(args.env.cmd, list) and len(args.env.cmd) > 0:
            command = args.env.cmd
        else:
            command = [args.info.binary.path]

        delete_unexpected_keyword(args.env.kwargs, ["env"])

        io = gdb.debug(command, **args.env.kwargs)
        io.process_mode = "debug"

    else:
        from pwnkit import parser
        parser.print_help()
        exit(0)

    return io
