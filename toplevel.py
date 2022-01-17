import PwnT00ls as pt
from PwnT00ls.lib.logger import *

try:
    from PwnT00ls.lib import *
    from PwnT00ls.osys import *
    from PwnT00ls.utils import *
except Exception as e:
    plog.error(e)

# import unnecessary modules
try:
    import traceback
    import ipdb
    from tqdm import tqdm

    from PwnT00ls import awd
except Exception as e:
    plog.warn(e)


# alias
pwn_the_world = pwnpwnpwn


__all__ = [x for x in globals().keys() if x != '__name__']
