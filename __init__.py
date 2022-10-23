import pwnutils as pu
from pwnutils.lib.logger import plog, tlog


try:
    from pwnutils import osys
    from pwnutils import lib

    from pwnutils.lib import parser
    from pwnutils.lib.entry import pppwn
    from pwnutils.lib.tools import *
except Exception as e:
    plog.error(e)


try:
    from pwn import *
except Exception as e:
    plog.error(e)

try:
    import traceback
    import ipdb
    from tqdm import tqdm
except Exception as e:
    plog.warn(e)


# alias
pwn_the_world = pppwn


# init
GDS = {}
BPL = []
GDB_SCRIPT = ""
