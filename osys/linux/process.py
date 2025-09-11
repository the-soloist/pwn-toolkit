#!/usr/bin/env python

import psutil
from pwnkit.lib.log import plog


def kill_pid(pid):
    """Kill a process by its PID."""
    try:
        psutil.Process(pid).kill()
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False


def get_pid_by_name(name):
    """Get a list of PIDs for processes with the given name."""
    pid_list = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            if proc.info['name'] == name:
                pid_list.append(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return pid_list


def kill_process_by_name(name):
    """Kill all processes with the given name and log the result."""
    pid_list = get_pid_by_name(name)

    if not pid_list:
        plog.info(f"No processes found with name: {name}")
        return

    killed_pids = []
    for pid in pid_list:
        if kill_pid(pid):
            killed_pids.append(pid)

    if killed_pids:
        plog.info(f"Killed {name} processes with PIDs: {killed_pids}")
    else:
        plog.warning(f"Failed to kill any {name} processes")
