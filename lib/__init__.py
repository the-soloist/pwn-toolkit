from . import cache
from . import color
from . import config
from . import convert
from . import crypto
from . import debug
from . import entry
from . import logger
from . import tubes


def try_import(path, name):
    try:
        exec(f"from {path} import {name}")
    except Exception as e:
        print(f"cannot import lib.{name}, exception: {e}.")


try_import(".", "database")
try_import(".", "emu")
try_import(".", "encode")
try_import(".", "http")


parser = config.init_parser()

del try_import


__all__ = [x for x in globals().keys() if x != '__name__']
