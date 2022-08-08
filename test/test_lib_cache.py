#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn_utils import *
from pwn_utils.osys.linux.rop import *


start = time.time()
ONE = one.get_one_gadget_list("libc.so.6")
end = time.time()

print(ONE)
print(end - start)
