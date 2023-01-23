#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from pwn import process, remote, gdb, log, pause, context

__all__ = [
    "pppwn"
]


def delete_unexpected_keyword(arg, klist):
    for k in klist:
        try:
            arg.pop(k)
        except:
            pass


def pppwn(args, force=None):
    assert type(args.cmd) == list
    assert type(args.kwargs) == dict

    if force:
        """ sh = pppwn(args, force="remote") """
        log.info(f"set {force} mode")
        setattr(args, force, True)

    # set context.terminal
    if os.getenv("TMUX"):
        if len(context.terminal) == 0:
            split_horizon = os.get_terminal_size().columns - 90
            context.terminal = ["tmux", "sp", "-h", "-l", str(split_horizon)]
            log.info(f"set `context.terminal = {str(context.terminal)}`")

    # set log level
    if args.verbose:
        if args.verbose == 1:
            context.log_level = "debug"
        else:
            log.setLevel(0)

    if args.remote:
        host, port = args.target
        sh = remote(host, port)
        sh.process_mode = "remote"

    elif args.websocket:
        from pwnutils.lib.tubes import websocket
        sh = websocket(args.target)
        sh.process_mode = "websocket"

    elif args.local:
        """ 
        Run with local mode:

        >>> sh = process([ld.path, binary.path], env={"LD_PRELOAD": libc.path})
        >>> sh = process([f"qemu-{context.arch}", "-g", "9999", "-L", ".", binary.path])

        >>> args.cmd = [ld.path, binary.path]
        >>> args.kwargs = {
                "env": {"LD_PRELOAD": "/path/to/libc.so"},  # libc.path
            }

        Run with qemu: 
        1. add gdb script:
            ```
            file {file_path}
            target remote :9999
            format(file_path=binary.path, **locals())
            ```

        2. add to py
            ```
            from pwnutils.osys.linux.elf.process import kill_process_by_name
            kill_process_by_name("qemu")
            ```

        >>> args.cmd = [
                f"qemu-{context.arch}", 
                "-g", "9999", 
                "-L", ".", binary.path
            ]
        or 
        >>> args.cmd = ["./run.sh"]

        >>> sh = pppwn(args)
        """

        if args.cmd == list():
            command = args.binary.path
        else:
            command = args.cmd

        local_black_list = ["gdbscript"]
        delete_unexpected_keyword(args.kwargs, local_black_list)

        sh = process(command, **args.kwargs)
        sh.process_mode = "local"

    elif args.debug:
        """ 
        Run with debug mode:

        >>> args.kwargs = {"gdbscript": GDB_SCRIPT, }
        >>> sh = pppwn(args)
        """

        if args.cmd == list():
            command = args.binary.path
        else:
            command = args.cmd

        debug_black_list = ["env"]
        delete_unexpected_keyword(args.kwargs, debug_black_list)

        sh = gdb.debug(command, **args.kwargs)
        sh.process_mode = "debug"

    else:
        from pwnutils.lib import parser
        parser.print_help()
        exit(0)

    return sh
