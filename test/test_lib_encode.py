#!/usr/bin/env python
# -*- coding: utf-8 -*-

from PwnT00ls.lib.convert.type2 import *
from PwnT00ls.osys.linux.elf.mem import str2mem


s1 = "/path/to/flag"
n1 = str2int(s1, endian="little")

print(long_to_bytes(n1))
print(hex(n1))
print(int2str(n1, endian="little"))

res = str2mem(s1)
for i in res:
    print(hex(i), int2str(i))
