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
    "dbgsrv,"
    "init_debug_server",
    "tube_debug",
]


@dataclass
class DebugServer:
    is_register: bool = False

    HOST: str = "127.0.0.1"
    SERVICE_PORT = 9541
    COMMAND_PORT: int = 9545
    GDBSERVER_PORT: int = 9549

    COMMAND_GDB_REGISTER: int = 0x01
    COMMAND_GDB_LOGOUT: int = 0x05
    COMMAND_GDBSERVER_ATTACH: int = 0x02
    COMMAND_STRACE_ATTACH: int = 0x03
    COMMAND_GET_ADDRESS: int = 0x04
    COMMAND_RUN_SERVICE: int = 0x06

    def __del__(self):
        self.logout()

    def _sock_send_once(self, payload):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)  # UDP
        sock.sendto(payload, (self.HOST, self.COMMAND_PORT))
        data, address = sock.recvfrom(0x1000)
        sock.close()
        return data, address

    def init(self, host="", connect=False, wait=0) -> remote | tuple[str, int]:
        """ 
        Arguments:
            host(str): set debug server host
            connect(bool): connect to server port, usually for debug web server
        """
        if host:
            self.HOST = host

        kill_process_by_name("gdb")
        kill_process_by_name("gdb-mutilarch")

        self.register()
        # plog.success(f"connect gdb with '{self.HOST}:{self.GDBSERVER_PORT}'")

        if connect:
            p = remote(self.HOST, self.SERVICE_PORT)
            time.sleep(wait)
            return p
        else:
            return self.HOST, self.SERVICE_PORT

    def register(self):
        self._sock_send_once(struct.pack("B", self.COMMAND_GDB_REGISTER))
        self.is_register = True

    def logout(self):
        if self.is_register:
            self._sock_send_once(struct.pack("B", self.COMMAND_GDB_LOGOUT))

    def attach_gdbserver(self, gdb_scripts="", gdb_args=[]) -> int | None:
        script_path = f"/tmp/temp_gdb_script"
        open(script_path, "w").write(gdb_scripts)

        data, _ = self._sock_send_once(struct.pack("BB", 0x02, len(script_path)) + script_path.encode())

        option = struct.unpack("B", data[:1])[0]
        assert option == self.COMMAND_GDBSERVER_ATTACH

        cmd = [
            gdb.binary(),
            "-q",
            "-ex", f"target remote {self.HOST}:{self.GDBSERVER_PORT}",
            "-x", script_path
        ] + gdb_args

        return misc.run_in_new_terminal(cmd)

    def attach_strace(self):
        self._sock_send_once(struct.pack("B", self.COMMAND_STRACE_ATTACH))

    def get_address(self, search_str):
        data, _ = self._sock_send_once(struct.pack('BB', 0x04, len(search_str.encode())) + search_str.encode())
        return data

    def run_service(self):
        self._sock_send_once(struct.pack("B", self.COMMAND_RUN_SERVICE))


dbgsrv: DebugServer = DebugServer()


def tube_debug(target, gdbscript="", gds: dict = {}, bpl: list = [], exe=None, gdb_args=[], ssh=None, sysroot=None, api=False):
    """
    Arguments:
      bpl: break point list
      gds: gdb debug symbols
    """

    if not isinstance(target, tube):
        gdb.attach(target, gdbscript, exe=exe, gdb_args=gdb_args, ssh=ssh, sysroot=sysroot, api=api)

    process_mode = None
    if hasattr(target, "_process_mode"):
        process_mode = getattr(target, "_process_mode")

    # pass remote mode
    if process_mode and not dbgsrv.is_register:
        if process_mode in ["remote", "websocket"]:
            plog.warning(f"not support debug in {process_mode} mode")
            return
        elif process_mode == "debug":
            plog.warning("duplicate debug process")
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

    if process_mode in ["remote", "websocket"] and dbgsrv.is_register:
        dbgsrv.attach_gdbserver(scripts, gdb_args)
        pause()

    else:
        gdb.attach(target, scripts, exe=exe, gdb_args=gdb_args, ssh=ssh, sysroot=sysroot, api=api)

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
