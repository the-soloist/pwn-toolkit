#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import process, remote, gdb, log


def delete_unexpected_keyword(arg, klist):
    for k in klist:
        try:
            arg.pop(k)
        except:
            pass


def pwnpwnpwn(args, force=None):
    assert type(args.cmd) == list
    assert type(args.kwargs) == dict

    if force:
        """ sh = pwnpwnpwn(args, force="remote") """
        log.info(f"set {force} mode")
        setattr(args, force, True)

    if args.remote:
        host, port = args.target
        sh = remote(host, port)

    elif args.local:
        """ 
        Run local mode:

        >>> sh = process([ld.path, binary.path], env={"LD_PRELOAD": libc.path})
        >>> sh = process([f"qemu-{context.arch}", "-g", "9999", "-L", ".", binary.path])

        >>> args.cmd = [ld.path, binary.path]
        >>> args.kwargs = {
                "env": {"LD_PRELOAD": "/path/to/libc.so"},  # libc.path
            }

        Run with qemu: 
        1. add gdb script:
            file {file_path}
            target remote :9999
            format(file_path=binary.path, **locals())

        2. run pt.osys.linux.elf.process.kill_process_by_name("qemu")

        >>> args.cmd = [
                f"qemu-{context.arch}", 
                "-g", "9999", 
                "-L", ".", binary.path
            ]

        or 
        >>> args.cmd = "./run.sh"

        >>> sh = pwnpwnpwn(args)
        """

        if args.cmd == list():
            command = args.binary.path
        else:
            command = args.cmd

        local_black_list = ["gdbscript"]
        delete_unexpected_keyword(args.kwargs, local_black_list)

        sh = process(command, **args.kwargs)

    elif args.debug:
        """ 
        Debug mode usage:

        >>> args.kwargs = {"gdbscript": GDB_SCRIPT, }
        >>> sh = pwnpwnpwn(args)
        """

        if args.cmd == list():
            command = args.binary.path
        else:
            command = args.cmd

        debug_black_list = ["env"]
        delete_unexpected_keyword(args.kwargs, debug_black_list)

        sh = gdb.debug(command, **args.kwargs)
    else:
        from PwnT00ls.utils import parser
        parser.print_help()
        exit(0)

    return sh
