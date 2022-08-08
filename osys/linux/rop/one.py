#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess


def get_one_gadget_list(filename):
    # return list(map(int, subprocess.check_output(['one_gadget', '--raw', filename]).split(b' ')))
    from pwn_utils.lib.cache import CmdCache

    cc = CmdCache(
        cmd=['one_gadget', '--raw', "$filename"],
        filename=filename,
        handler=lambda exec_args: list(map(int, subprocess.check_output(exec_args).split(b' '))),
    )

    if cc.search():
        return cc.result
    else:
        cc.run()
        cc.save()
        return cc.result
