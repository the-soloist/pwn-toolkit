#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwnutils.core.decorates import use_pwnio
from pwnutils.lib.convert import type2
from pwnutils.lib.crypto.crack import do_hash_pow, do_hash_pow_m
from pwnutils.lib.debug import GDB_SPLITMIND_CONFIG
from pwnutils.lib.tubes import cat_flag, recv_flag