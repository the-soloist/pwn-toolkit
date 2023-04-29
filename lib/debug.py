#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import gdb, tube, pause
from pwnutils.lib.logger import plog


__all__ = [
    "tube_debug",
]


def tube_debug(_tube: tube, gdbscript="", gds: dict = {}, bpl: list = [], force=False):
    """
    Arguments:
      bpl: break point list
      gds: gdb debug symbols
    """

    # pass remote mode
    if hasattr(_tube, "process_mode") and not force:
        if _tube.process_mode in ["remote", "websocket"]:
            plog.warning(f"not support debug in {_tube.process_mode} mode")
            return
        elif _tube.process_mode == "debug":
            plog.warning(f"duplicate debug process")
            return

    script_lines = list()

    # add gdb debug symbols
    for k, v in gds.items():
        s = "set ${k}={v}".format(k=k, v=str(v))
        script_lines.append(s)

    # add break point list
    for b in bpl:
        s = "b *{b}".format(b=str(b))
        script_lines.append(s)

    script_lines.append(gdbscript)
    res = "\n".join(script_lines)

    # plog.info(f"exec gdb script:\n{res}")
    gdb.attach(_tube, res)

    if hasattr(_tube, "process_mode") and _tube.process_mode == "ssh":
        plog.waitfor(f"waiting remote process attached")
        pause()
