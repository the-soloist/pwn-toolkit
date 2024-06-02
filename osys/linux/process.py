#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import psutil


def kill_pid(pid):
    try:
        psutil.Process(pid).kill()
    except:
        pass


def get_pid_by_name(name):
    pid_list = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] == name:
                pid_list.append(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return pid_list


def kill_process_by_name(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] == process_name:
                proc.kill()
                print(f"Killed process {process_name} with PID {proc.info['pid']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass


def kill_process_by_name(name):
    from pwnkit.lib.log import plog

    pid_list = get_pid_by_name(name)

    for p in pid_list:
        kill_pid(p)
    plog.info(f"kill {name} process, pid: {pid_list}")
