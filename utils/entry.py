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
    if force:
        """ sh = pwnpwnpwn(args, force="remote") """
        log.info(f"set {force} mode")
        setattr(args, force, True)

    if args.remote:
        host, port = args.target
        sh = remote(host, port)

    elif args.local:
        sh = process(args.binary.path)

    elif args.env:
        """ Qemu/Env mode usage:

        Env mode demo:
        >>> sh = process([ld.path, binary.path], env={"LD_PRELOAD": libc.path})
        >>> sh = process([f"qemu-{context.arch}", "-g", "9999", "-L", ".", binary.path])

        >>> args.cmd = [ld.path, binary.path]
        >>> args.kwargs = {
                "env": {"LD_PRELOAD": "/path/to/libc.so"},  # libc.path
            }

        Qemu mode:
        1. add gdb script to GDB_SCRIPT:
            file {file_path}
            target remote :9999

            format(file_path=binary.path, **locals())

        2. run pt.osys.linux.elf.process.kill_process_by_name("qemu")

        Qemu mode demo: 
        >>> args.cmd = [
                f"qemu-{context.arch}", 
                "-g", "9999", 
                "-L", ".", binary.path
            ]

        or 
        >>> args.cmd = "./run.sh"

        >>> sh = pwnpwnpwn(args)
        """

        assert "cmd" in args
        if args.cmd is None:
            print("read usage first")
            exit()

        eq_black_list = ["gdbscript"]
        delete_unexpected_keyword(args.kwargs, eq_black_list)

        sh = process(args.cmd, **args.kwargs)

    elif args.debug:
        """ Debug mode usage:

        >>> args.kwargs = { 
                "gdbscript": GDB_SCRIPT, 
            }
        >>> sh = pwn_the_world(args)
        """

        dbg_black_list = ["env"]
        delete_unexpected_keyword(args.kwargs, dbg_black_list)

        sh = gdb.debug(args.binary.path, **args.kwargs)

    else:
        from PwnT00ls.utils import parser
        parser.print_help()
        exit(0)

    return sh
