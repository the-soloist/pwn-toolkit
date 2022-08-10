#!/usr/bin/env python
# -*- coding: utf-8 -*-

from qiling import Qiling


def is_stack_variable(ql: Qiling, var):
    global STACK_MAP

    if "STACK_MAP" not in locals().keys():
        # get stack map info
        map_info = ql.mem.map_info
        for _map in map_info:
            if "[stack]" == _map[-1]:
                STACK_MAP = _map
                stack_start = _map[0]
                stack_end = _map[1]

    if stack_start <= var <= stack_end:
        return True

    return False


def close_printf(ql: Qiling, *args):
    pass
