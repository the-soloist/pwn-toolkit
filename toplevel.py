import PwnT00ls as pt
from PwnT00ls.lib.logger import plog, tlog

try:
    from PwnT00ls import lib as pt_lib
    from PwnT00ls import osys as pt_os
    from PwnT00ls import utils as pt_util

    from PwnT00ls.lib import parser
    from PwnT00ls.utils import *
except Exception as e:
    plog.error(e)


# import unnecessary modules
try:
    import traceback
    import ipdb
    from tqdm import tqdm

    from PwnT00ls import awd as pt_awd
    from PwnT00ls import pkg as pt_pkg
except Exception as e:
    plog.warn(e)


# alias
pwn_the_world = pwnpwnpwn


__all__ = [x for x in globals().keys() if x != '__name__']
