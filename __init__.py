import pwnkit as pk
from pwnkit.toplevel import *


# alias
autopwn = pwn_the_world = pwntube  # XD
parser = core.config.init_parser()

# init
GDS = {}
BPL = []
GDB_SCRIPT = ""
pwnobj = core.classes.EmptyClass()
