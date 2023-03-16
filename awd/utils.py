#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from pathlib import Path
from pwn import context
from pwnutils.lib.logger import plog


__all__ = [
    "run"
]


def run(args, exploit_fn, submit_fn=None, save_fp=None):
    target_list = json.load(open(args.target_list, "r"))

    for hp in target_list:
        host, port = hp.values()
        plog.info(f"exploiting {host}:{port}")

        try:
            context.log_level = "warning"
            sh = remote(host, port)
            flag = exploit_fn(sh)
            sh.close()
            context.log_level = "info"

            plog.success(f"get flag success: {flag}")
        except Exception as e:
            plog.warning(f"get flag failed, error: {e}")
            continue

        if not flag:
            plog.warning(f"not found flag")
            continue

        if submit_fn and flag:
            try:
                res = submit_fn(flag)
                plog.success(f"submit success, resp: {res}")
            except Exception as e:
                plog.warning(f"submit failed, error: {e}")

        if save_fp and flag:
            save_fp.write(f"{host}:{port} -> {flag}\n")
        elif save_fp and not flag:
            save_fp.write(f"{host}:{port} not found flag\n")
