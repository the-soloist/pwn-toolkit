#!/usr/bin/env python
# -*- coding: utf-8 -*-

from websocket import WebSocket, ABNF, WebSocketException, WebSocketTimeoutException
from pwn import u64
from pwnlib.tubes.tube import tube
from pwnutils.lib.debug import tube_debug
from pwnutils.lib.logger import plog


__all__ = [
    "websocket",
    "recv_pointer",
]


default_delims = {
    "heap": [b"\x55", b"\x56"],
    "libc": [b"\x7f"],
    "stack": [b"\xfd\x7f", b"\xfe\x7f", b"\xff\x7f"],
}


class websocket(tube):
    # Edit from https://gist.github.com/frankli0324/795162a14be988a01e0efa0531f7ac5a
    def __init__(self, url, headers=None, *args, **kwargs):
        if headers is None:
            headers = {}
        super(websocket, self).__init__(*args, **kwargs)
        self.closed = False
        self.sock = WebSocket()
        self.url = url
        self.sock.connect(url, header=headers)

    def recv_raw(self, numb):
        if self.closed:
            raise EOFError

        while True:
            try:
                data = self.sock.recv()
                if isinstance(data, str):
                    data = data.encode()
                break
            except WebSocketTimeoutException:
                return None
            except WebSocketException:
                self.shutdown("recv")
                raise EOFError

        if not data:
            self.shutdown()
            raise EOFError('Recv Error')

        return data

    def send_raw(self, data):
        if self.closed:
            raise EOFError

        try:
            self.sock.send_binary(data)
        except WebSocketException as e:
            self.shutdown()
            raise EOFError('Send Error')

    def settimeout_raw(self, timeout):
        if getattr(self, 'sock', None):
            self.sock.settimeout(timeout)

    def connected_raw(self, direction):
        try:
            self.sock.ping()
            opcode, data = self.sock.recv_data(True)
            return opcode == ABNF.OPCODE_PONG
        except:
            return False

    def close(self):
        if not getattr(self, 'sock', None):
            return

        self.closed = True

        self.sock.close()
        self.sock = None
        self._close_msg()

    def _close_msg(self):
        self.info('Closed connection to %s', self.url)

    def shutdown_raw(self, direction):
        if self.closed:
            return

        self.closed = True
        self.sock.shutdown()


def recv_pointer(_tube: tube, delims=None, off=6, name=None, byteorder="little", **kwargs):
    if not delims:
        delims = default_delims[name]

    res = _tube.recvuntil(delims, **kwargs)

    if res:
        addr = int.from_bytes(res[-off:], byteorder=byteorder)
        plog.debug(f"found pointer: {hex(addr)}")
    else:
        addr = None
        plog.warning(f"no pointers with the prefix {delims} found")

    return addr


# add new tube function
tube.proc_debug = tube.dbg = tube_debug
tube.recv_pointer = tube.rp = recv_pointer

# add tube alias
tube.s = tube.send
tube.sa = tube.sendafter
tube.sl = tube.sendline
tube.sla = tube.sendlineafter
tube.r = tube.recv
tube.rl = tube.recvline
tube.ru = tube.recvuntil


if __name__ == "__main__":
    t = tube()
    t.recv_raw = lambda n: b"\x01\x02\x03\x04\x05\x06\xff\x7f\x56\xaa\xaaFoo\nBar\nBaz\nKaboodle\n"
    r.rp([b"\x7f"])
