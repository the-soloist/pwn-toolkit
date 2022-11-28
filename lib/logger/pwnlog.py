#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from pwn import log
from pwnlib.exception import PwnlibException
from pwnlib.log import Logger
from pwnutils.lib.color import *
from tqdm import tqdm


__all__ = [
    "info", "success", "warn", "error",
    "PwnLogger", "TqdmLogger"
]


info = f"[{prefix_info}*{end}] "
success = f"[{prefix_success}+{end}] "
warn = f"[{prefix_warn}!{end}] "
error = f"[{prefix_error}ERROR{end}] "


class PwnLogger(Logger):
    def __init__(self):
        logger = logging.getLogger("pwnlib.pwnutils")
        self._logger = logger

        self._save = {"info": self.info,
                      "success": self.success,
                      "warn": self.warn,
                      "error": self.error,
                      "address": self.address}

        self._write = TqdmLogger._write

    def address(self, __msg_log_level="success", **kwargs):
        for k, v in kwargs.items():
            self._log(logging.INFO, f"{k} -> {hex(v)}", (), {}, __msg_log_level)

    def value(self, __msg_log_level="success", **kwargs):
        for k, v in kwargs.items():
            self._log(logging.INFO, f"{k}={v}", (), {}, __msg_log_level)

    def msg(self, __msg_log_level="info", **kwargs):
        for k, v in kwargs.items():
            self._log(logging.INFO, f"{k}: {v}", (), {}, __msg_log_level)

    def _write(self, msg):
        pass

    def switch_tqdm(self):
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

    def _log(self, msg, msgtype):
        print_log = getattr(self, msgtype)
        print_log(msg)

    def info(self, msg):
        self._write(f"{info}{msg}{end}")

    def success(self, msg):
        self._write(f"{success}{msg}{end}")

    def warn(self, msg):
        self._write(f"{warn}{msg}{end}")

    def error(self, msg):
        self._write(f"{error}{msg}{end}")
        raise PwnlibException(msg)

    def address(self, __msg_log_level="success", **kwargs):
        for k, v in kwargs.items():
            self._log(f"{k} -> {hex(v)}", __msg_log_level)

    def value(self, __msg_log_level="success", **kwargs):
        for k, v in kwargs.items():
            self._log(f"{k}={v}", __msg_log_level)

    def msg(self, __msg_log_level="info", **kwargs):
        for k, v in kwargs.items():
            self._log(f"{k}: {v}", __msg_log_level)
