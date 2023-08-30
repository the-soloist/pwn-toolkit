#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import subprocess


def kill_pid(pid):
    os.system(f"kill -9 {pid}")


def get_pid_by_name(name):
    cmd = f"kill -9 $(pgrep {name})"  # ps aux | grep -v grep | grep qemu | awk '{print $2}'
    subp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res = [x.decode() for x in subp.communicate() if x.decode()]

    if len(res) == 0:
        return None
    else:
        pid = [x for x in res[0].split('\n') if x]
        return pid


def kill_process_by_name(name):
    from pwnkit.lib.log import plog

    pid = get_pid_by_name(name)

    if pid is not None:
        for p in pid:
            kill_pid(p)
        plog.info(f"kill {name} process, pid: {pid}")
    else:
        plog.warning(f"not found '{name}' process")
