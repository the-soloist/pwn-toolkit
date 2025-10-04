#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from pwnlib.exception import PwnlibException
from pwnlib.log import console, Formatter, Logger
from pwnlib.term import text
from tqdm import tqdm

from pwnkit.core import color

__all__ = [
    "PwnLogger",
    "plog",
    "TqdmLogger",
    "tlog",
]


_msgtype_prefixes = {
    "status": [text.magenta, "x"],
    "success": [text.bold_green, "+"],
    "failure": [text.bold_red, "-"],
    "debug": [text.bold_red, "DEBUG"],
    "info": [text.bold_blue, "*"],
    "warning": [text.bold_yellow, "!"],
    "error": [text.on_red, "ERROR"],
    "exception": [text.on_red, "ERROR"],
    "critical": [text.on_red, "CRITICAL"],
    "info_once": [text.bold_blue, "*"],
    "warning_once": [text.bold_yellow, "!"],
    "address": [text.magenta, f"{color.Fore.LIGHTMAGENTA_EX}ADDR"],
    "value": [text.cyan, f"{color.Fore.LIGHTCYAN_EX}VALUE"],
    "message": [text.white, f"{color.Fore.LIGHTWHITE_EX}MSG"],
}


class LogFormatter(Formatter):
    def format(self, record):
        msg = super(Formatter, self).format(record)

        msgtype = getattr(record, "pwnlib_msgtype", None)

        if msgtype is None:
            return msg

        if msgtype in _msgtype_prefixes:
            style, symb = _msgtype_prefixes[msgtype]
            prefix = "[%s] " % style(symb)
        elif msgtype == "indented":
            prefix = self.indent
        elif msgtype == "animated":
            prefix = ""
        else:
            prefix = "[?] "

        msg = prefix + msg
        msg = self.nlindent.join(msg.splitlines())
        return msg


class PwnLogger(Logger):
    def __init__(self):
        logger = logging.getLogger("pwnlib.pwnkit")
        self._logger = logger

    def address(self, **kwargs):
        for k, v in kwargs.items():
            self._log(logging.INFO, f"{k} -> {hex(v)}", (), {}, "address")

    def value(self, _print_hex=True, **kwargs):
        for k, v in kwargs.items():
            self._log(logging.INFO, f"{k} = {hex(v) if _print_hex else v}", (), {}, "value")

    def message(self, name, msg):
        self._log(logging.INFO, f"{name}: {msg}", (), {}, "message")

    def msg(self, name, msg):
        self.message(name, msg)


class TqdmLogger(object):
    text_info = f"[{color.prefix_info}*{color.end}] "
    text_success = f"[{color.prefix_success}+{color.end}] "
    text_warning = f"[{color.prefix_warn}!{color.end}] "
    text_error = f"[{color.prefix_error}ERROR{color.end}] "

    text_address = f"[{color.Fore.LIGHTMAGENTA_EX}ADDR{color.end}] "
    text_value = f"[{color.Fore.LIGHTCYAN_EX}VALUE{color.end}] "
    text_message = f"[{color.Fore.LIGHTWHITE_EX}MSG{color.end}] "

    def _write(self, msg):
        try:
            tqdm.write(msg)
        except Exception as e:
            self.error(str(e))

    def _log(self, msg, msgtype):
        prefix = getattr(self, f"text_{msgtype}")
        self._write(f"{prefix}{msg}{color.end}")

    def info(self, msg):
        self._log(msg, "info")

    def success(self, msg):
        self._log(msg, "success")

    def warning(self, msg):
        self._log(msg, "warning")

    def warn(self, msg):
        self.warning(msg)

    def error(self, msg):
        self._log(msg, "error")
        raise PwnlibException(msg)

    def address(self, **kwargs):
        for k, v in kwargs.items():
            self._log(f"{k} -> {hex(v)}", "address")

    def value(self, _print_hex=True, **kwargs):
        for k, v in kwargs.items():
            self._log(f"{k} = {hex(v) if _print_hex else v}", "value")

    def message(self, name, msg):
        self._log(f"{name}: {msg}", "message")

    def msg(self, name, msg):
        self.message(name, msg)


console.setFormatter(LogFormatter())

plog = PwnLogger()
tlog = TqdmLogger()


if __name__ == "__main__":
    # import ipdb
    # ipdb.set_trace()

    plog.address(test=0xDEADBEEF)
    plog.value(test=0xDEADBEEF)
    plog.value(False, test=0xDEADBEEF)
    plog.msg("test", "message")

    plog.info("test")
    plog.warn("test")
    plog.success("test")
    plog.waitfor("test")

    try:
        plog.error("test")
    except:
        pass

    tlog.address(test=0xDEADBEEF)
    tlog.value(test=0xDEADBEEF)
    tlog.value(False, test=0xDEADBEEF)
    tlog.msg("test", "test message")

    tlog.info("test")
    tlog.warn("test")
    tlog.success("test")

    try:
        tlog.error("test")
    except:
        pass
