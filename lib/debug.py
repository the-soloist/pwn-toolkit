#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import log, gdb, u32, u64, tube, pause


def pdebug(sh, gdbscript="", bpl=[], gds={}):
    """ old debug """

    script_lines = list()

    # add break point list
    for b in BPS:
        s = "b *{b}".format(b=str(b))
        script_lines.append(s)

    # add gdb debug symbol
    for k, v in GDS.items():
        s = "set ${k}={v}".format(k=k, v=str(v))
        script_lines.append(s)

    script_lines.append(gdbscript)
    res = "\n".join(script_lines)

    log.info("exec gdb script:\n" + res)
    gdb.attach(sh, res)


class PwnTube(tube):
    """ pwn_utils Tube """

    def dbg(self, gdbscript="", gds: dict = {}, bpl: list = []):
        """
        @param bpl: break point list
        @param gds: gdb debug symbols
        """

        # pass remote mode
        if hasattr(self, "process_mode"):
            if self.process_mode != "local":
                # TODO add support for remote debug
                log.warning(f"not support remote debug, for now.")
                # pause()
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

        # log.info(f"exec gdb script:\n{res}")
        gdb.attach(self, res)


tube.dbg = PwnTube.dbg
