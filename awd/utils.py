#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pathlib import Path
from pwn import context, remote
from pwnutils.lib.log import plog

__all__ = [
    "run"
]


def parse_target_list(path: Path):
    fp = open(path, "r")
    content = fp.read().strip().split("\n")
    fp.close()
    return [tuple(x.split(":")) for x in content if x]


def run(args, exploit_fn, submit_fn=None, target_list=[], log_fp=None):
    failed_list = []

    if len(target_list) == 0:
        plog.warning("no host in target list")
        return failed_list

    for target in target_list:
        host, port = target
        plog.info(f"exploiting {host}:{port}")
        context.log_level = "debug"

        get_flag_status = False
        submit_status = False

        try:
            io = remote(host, port)
            flag = exploit_fn(io)
            io.close()

            get_flag_status = True
            plog.success(f"get flag success: {flag}")
        except Exception as e:
            plog.warning(f"get flag failed, error: {e}")
            failed_list.append((host, port))  # 获取flag失败
            continue

        if not get_flag_status:
            plog.warning(f"not found flag")
            failed_list.append((host, port))  # 获取空flag
            continue

        if submit_fn and flag:
            try:
                res = submit_fn(flag)
                plog.success(f"submit success, resp: {res}")
            except Exception as e:
                plog.warning(f"submit failed, error: {e}")

        if log_fp and flag:
            log_fp.write(f"{host}:{port} -> {flag}\n")
        elif log_fp and not flag:
            log_fp.write(f"{host}:{port} not found flag\n")

    return failed_list
