#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import gdb, tube, pause

from pwnkit.lib.log import plog


__all__ = [
    "GDB_SPLITMIND_CONFIG",
    "tube_debug",
]


GDB_SPLITMIND_CONFIG = {
    # focus on disasm pane
    "disasm": """python
import splitmind
(splitmind.Mind()
  .tell_splitter(show_titles=True)
  .tell_splitter(set_title="main")

  .above(display="legend", of="first", size="60%")
  .show("regs", on="legend")
  .below(display="stack", of="legend", size="35%")

  .above(display="disasm", of="main", size="50%")
  .right(display="code", of="disasm", size="30%")
  .below(display="backtrace", of="code", size="60%")
).build(nobanner=True)
end

set context-stack-lines 8
set context-source-code-lines 15
set context-code-lines 20\n""",

    # focus on code pane
    "code": """python
import splitmind
(splitmind.Mind()
  .tell_splitter(show_titles=True)
  .tell_splitter(set_title="main")

  .above(display="disasm", of="first", size="70%")
  .below(display="legend", of="disasm", size="50%")
  .show("regs", on="legend")

  .above(display="code", of="main", size="65%")
  .below(display="stack", of="code", size="30%")
  .right(display="backtrace", of="stack", size="35%")
).build(nobanner=True)
end

set context-stack-lines 8
set context-source-code-lines 25
set context-code-lines 15\n"""
}


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

    lines = list()

    # add gdb debug symbols
    for k, v in gds.items():
        s = "set ${k}={v}".format(k=k, v=str(v))
        lines.append(s)

    # add break point list
    for b in bpl:
        s = "b *{b}".format(b=str(b))
        lines.append(s)

    lines.append(gdbscript)

    scripts = "\n".join(lines)
    gdb.attach(_tube, scripts)

    if hasattr(_tube, "process_mode") and _tube.process_mode == "ssh":
        plog.waitfor(f"waiting remote process attached")
        pause()
