#!/usr/bin/env python
# -*- coding: utf-8 -*-

import socket
import struct
import time

from dataclasses import dataclass
from pwnlib import gdb
from pwnlib.tubes.remote import remote
from pwnlib.tubes.tube import tube
from pwnlib.ui import pause
from pwnlib.util import misc

from pwnkit.lib.log import plog
from pwnkit.osys.linux.process import kill_process_by_name


__all__ = [
    "DEFAULT_SPLITMIND_CONFIG",
    "init_debug_server",
    "tube_debug",
]


@dataclass
class DebugServer:
    host: str = "127.0.0.1"
    cmd_port: int = 9545
    gdb_port: int = 9549
    sock: socket.socket = None
    init: bool = False

    command_gdb_register: int = 0x01
    command_gdbserver_attach: int = 0x02
    command_gdb_logout: int = 0x05


DEBUG_SERVER: DebugServer = DebugServer()


def init_debug_server(host="", connect=False, wait=1) -> tube:
    """ 
    Arguments:
        host(str): set debug server host
        connect(bool): connect to server port, usually for debug web server
    """
    if host:
        DEBUG_SERVER.host = host

    kill_process_by_name("gdb")
    kill_process_by_name("gdb-mutilarch")

    DEBUG_SERVER.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
    DEBUG_SERVER.sock.sendto(struct.pack("B", DEBUG_SERVER.command_gdb_register), (DEBUG_SERVER.host, DEBUG_SERVER.cmd_port))

    DEBUG_SERVER.init = True

    if connect:
        p = remote("127.0.0.1", 9541)
        time.sleep(wait)
        return p
    else:
        return None


def tube_debug(_tube: tube, gdbscript="", gds: dict = {}, bpl: list = []):
    """
    Arguments:
      bpl: break point list
      gds: gdb debug symbols
    """

    process_mode = None
    if hasattr(_tube, "process_mode"):
        process_mode = getattr(_tube, "process_mode")

    # pass remote mode
    if process_mode and not DEBUG_SERVER.init:
        if process_mode in ["remote", "websocket"]:
            plog.warning(f"not support debug in {process_mode} mode")
            return
        elif process_mode == "debug":
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

    if process_mode in ["remote", "websocket"] and DEBUG_SERVER.init:
        script_path = f"/tmp/empty_gdb_script"
        open(script_path, "w").write(scripts)
        DEBUG_SERVER.sock.sendto(struct.pack("BB", 0x02, len(script_path)) + script_path.encode(), (DEBUG_SERVER.host, DEBUG_SERVER.cmd_port))

        while True:
            data, _ = DEBUG_SERVER.sock.recvfrom(4096)
            option = struct.unpack("B", data[:1])[0]
            if option == DEBUG_SERVER.command_gdbserver_attach:
                break

        cmd = [gdb.binary(), "-q", "-ex", f"target remote {DEBUG_SERVER.host}:{DEBUG_SERVER.gdb_port}", "-x", script_path]
        misc.run_in_new_terminal(cmd)
        pause()

    else:
        gdb.attach(_tube, scripts)

        if process_mode == "ssh":
            plog.waitfor(f"waiting remote process attached")
            pause()


DEFAULT_SPLITMIND_CONFIG = {
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
