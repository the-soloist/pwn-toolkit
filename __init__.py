import pwnkit as pk
from pwnkit.toplevel import *


# alias
autopwn = pwn_the_world = pwntube  # XD
parser = core.config.init_parser()

# init
GDB_DEBUG_SYMBOLS = {}
GDB_BREAKPOINTS = []
GDB_SCRIPT = ""
pwnobj = core.classes.EmptyClass()
