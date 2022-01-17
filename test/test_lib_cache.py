#!/usr/bin/env python
# -*- coding: utf-8 -*-

from PwnT00ls import *
from PwnT00ls.osys.linux.rop import *


start = time.time()
ONE = one.get_one_gadget_list("libc.so.6")
end = time.time()

print(ONE)
print(end - start)
