import pwn_utils as pwnutils
from pwn_utils.lib.logger import plog, tlog


try:
    from pwn_utils.lib import parser
    from pwn_utils.lib.entry import pwnpwnpwn
    from pwn_utils.lib.tools import *
except Exception as e:
    plog.error(e)


try:
    import traceback
    import ipdb
    from tqdm import tqdm
except Exception as e:
    plog.warn(e)


# alias
pwn_the_world = pwnpwnpwn
