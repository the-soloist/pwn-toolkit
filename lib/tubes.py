#!/usr/bin/env python
# -*- coding: utf-8 -*-

from websocket import WebSocket, ABNF, WebSocketException, WebSocketTimeoutException
from pwn import u64
from pwnlib.tubes.tube import tube
from pwnutils.lib.logger import plog


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


class PwnTube(tube):
    def recv_address(self, address_type, delims=None, off=6, timeout=1, verbose=True, **kwargs):
        if not delims:
            if address_type == "heap":
                delims = [b"\x55", b"\x56"]
            if address_type == "libc":
                delims = b"\x7f"
            if address_type == "stack":
                delims = [b"\x7f\xfd", b"\x7f\xfe", b"\x7f\xff"]

        res = self.recvuntil(delims, timeout=timeout, **kwargs)

        if res:
            addr = u64(res[-off:].ljust(8, b"\x00"))
        else:
            addr = None

        if verbose:
            plog.success(f"found {address_type} address -> {hex(addr)}")

        return addr


# add new tube function
tube.recv_address = PwnTube.recv_address

# add tube alias
tube.s = tube.send
tube.sa = tube.sendafter
tube.sl = tube.sendline
tube.sla = tube.sendlineafter
tube.r = tube.recv
tube.rl = tube.recvline
tube.ru = tube.recvuntil
tube.ia = tube.interactive
