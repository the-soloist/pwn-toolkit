#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from tqdm import tqdm
from pwn_utils.lib.logger import tlog


for i in tqdm(range(100)):
    # tlog.info("test info")
    # tlog.success("test success")
    # tlog.warn("test warn")
    # tlog.error("test error")
    # tlog.address("info", test_addr=0xdeadbeef + i)
    # tlog.value("info", test_value=str(i).encode())
    tlog.msg("info", test_msg=str(i).encode())
    time.sleep(0.1)
