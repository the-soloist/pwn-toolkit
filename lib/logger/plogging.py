#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import log
from pwnlib.exception import PwnlibException
from pwnlib.log import Logger
from PwnT00ls.lib.color.colors import *
from tqdm import tqdm
import logging


info = f"[{prefix_info}*{end}] "
success = f"[{prefix_success}+{end}] "
warn = f"[{prefix_warn}!{end}] "
error = f"[{prefix_error}ERROR{end}] "


class PwnLogger(Logger):
    def __init__(self):
        logger = logging.getLogger("pwnlib.PwnT00ls")
        self._logger = logger

        self._save = dict()
        self._save["info"] = self.info
        self._save["success"] = self.success
        self._save["warn"] = self.warn
        self._save["error"] = self.error
        self._save["address"] = self.address

        self._write = TqdmLogger._write

    def address(self, **kwargs):
        for k, v in kwargs.items():
            self._log(logging.INFO, f"{k} -> {hex(v)}", (), {}, 'success')

    def _write():
        pass

    def set_tqdm(self):
        for fname in self._save.keys():
            fbody = getattr(TqdmLogger, fname)
            setattr(self, fname, fbody)

    def quit_tqdm(self):
        for fname, fbody in self._save.items():
            setattr(self, fname, fbody)


class TqdmLogger(object):
    def _write(self, msg):
        try:
            tqdm.write(msg)
        except Exception as e:
            self.error(str(e))

    def info(self, msg):
        self._write(f"{info}{msg}")

    def success(self, msg):
        self._write(f"{success}{msg}")

    def warn(self, msg):
        self._write(f"{warn}{msg}")

    def error(self, msg):
        self._write(f"{error}{msg}")
        raise PwnlibException(msg)

    def address(self, **kwargs):
        for k, v in kwargs.items():
            self.success(f"{k} -> {hex(v)}")
