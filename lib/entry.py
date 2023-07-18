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
        """ sh = pwntube(args, force="remote") """
        log.info(f"set {force} mode")
        setattr(args, force, True)

    # set context.terminal
    if os.getenv("TMUX"):
        if len(context.terminal) == 0:
            split_horizon = os.get_terminal_size().columns - 90
            context.terminal = ["tmux", "sp", "-h", "-l", str(split_horizon)]
            log.debug(f"set `context.terminal = {str(context.terminal)}`")

    # set log level
    if args.verbose:
        from pwnutils.core.log import ulog

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
        host, port = args.info.target
        sh = remote(host, port)
        sh.process_mode = "remote"

    # websocket mode
    elif args.websocket:
        from pwnutils.lib.tubes import websocket
        sh = websocket(args.info.target)
        sh.process_mode = "websocket"

    elif args.ssh:
        from pwn import ssh as SSH

        assert hasattr(args.cli, "cmd")
        assert hasattr(args.cli, "kwargs")
        assert isinstance(args.cli.ssh, SSH)

        if isinstance(args.cli.cmd, list) and len(args.cli.cmd) > 0:
            command = args.cli.cmd
        else:
            command = args.info.binary.path

        sh = args.cli.ssh.process(command, **args.cli.kwargs)
        sh.process_mode = "ssh"

    # local mode
    elif args.local:
        """ 
        Run with local mode:

          >>> sh = process([ld.path, binary.path], env={"LD_PRELOAD": libc.path})
          >>> sh = process([f"qemu-{context.arch}", "-g", "9999", "-L", ".", binary.path])

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
            from pwnutils.osys.linux.elf.process import kill_process_by_name
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

        sh = process(command, **args.cli.kwargs)
        sh.process_mode = "local"

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

        sh = gdb.debug(command, **args.cli.kwargs)
        sh.process_mode = "debug"

    else:
        from pwnutils.lib import parser
        parser.print_help()
        exit(0)

    return sh
