import pwnutils as pu
from pwnutils.toplevel import *


# alias
pwn_the_world = pwntube
parser = core.config.init_parser()

# init
GDS = {}
BPL = []
GDB_SCRIPT = ""
pwnobj = core.classes.EmptyClass()
