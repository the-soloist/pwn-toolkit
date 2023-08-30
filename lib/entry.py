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
            context.log_level = "debug"
        elif args.verbose == 2:
            ulog.level("INFO")
        elif args.verbose == 3:
            ulog.level("DEBUG")
        else:
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
        from pwn import ssh as SSH

        assert hasattr(args.cli, "cmd")
        assert hasattr(args.cli, "kwargs")
        assert isinstance(args.cli.ssh, SSH)

        if isinstance(args.cli.cmd, list) and len(args.cli.cmd) > 0:
            command = args.cli.cmd
        else:
            command = args.info.binary.path

        io = args.cli.ssh.process(command, **args.cli.kwargs)
        io.process_mode = "ssh"

    # local mode
    elif args.local:
        """ 
        Run with local mode:

          >>> io = process([ld.path, binary.path], env={"LD_PRELOAD": libc.path})
          >>> io = process([f"qemu-{context.arch}", "-g", "9999", "-L", ".", binary.path])

          >>> args.cli.cmd = [ld.path, binary.path]
          >>> args.cli.kwargs = { "env": {"LD_PRELOAD": "/path/to/libc.so"}, }

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

          >>> args.cli.cmd = [f"qemu-{context.arch}", "-g", "9999", "-L", ".", binary.path]
          >>> args.cli.cmd = ["./run.sh"]

          >>> cat ./run.sh
          #!/bin/bash
          qemu-mips -g 9999 -L . /path/to/binary
        """

        assert hasattr(args.cli, "cmd")
        assert hasattr(args.cli, "kwargs")

        if isinstance(args.cli.cmd, list) and len(args.cli.cmd) > 0:
            command = args.cli.cmd
        else:
            command = args.info.binary.path

        delete_unexpected_keyword(args.cli.kwargs, ["gdbscript"])

        io = process(command, **args.cli.kwargs)
        io.process_mode = "local"

    # debug mode
    elif args.debug:
        """ 
        Run with debug mode:

          >>> args.cli.kwargs = {"gdbscript": GDB_SCRIPT, }
        """

        assert hasattr(args.cli, "cmd")
        assert hasattr(args.cli, "kwargs")

        if isinstance(args.cli.cmd, list) and len(args.cli.cmd) > 0:
            command = args.cli.cmd
        else:
            command = args.info.binary.path

        delete_unexpected_keyword(args.cli.kwargs, ["env"])

        io = gdb.debug(command, **args.cli.kwargs)
        io.process_mode = "debug"

    else:
        from pwnkit import parser
        parser.print_help()
        exit(0)

    return io
