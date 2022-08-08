#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn_utils.lib.logger import *


tlog.info("testing tqdm logger")
tlog.success("test")
tlog.warn("test")
# tlog.error("test")
tlog.addr(test_address=0xdeadbeef)

plog.info("testing pwn logger")
plog.success("test")
plog.warn("test")
# plog.error("test")
plog.addr(test_address=0xdeadbeef)
