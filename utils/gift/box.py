#!/usr/bin/env python

import datetime
import os
import stat
from paramiko import SFTPClient
from pathlib import Path
from rich.progress import track

from pwnkit.core.decorates import use_pwnio
from pwnkit.lib.convert import type2
from pwnkit.lib.crypto.crack import do_hash_pow, do_hash_pow_m
from pwnkit.lib.debug import DEFAULT_SPLITMIND_CONFIG
from pwnkit.lib.debug import tube_debug as gdb_debug
from pwnkit.lib.debug import dbgsrv
from pwnkit.lib.tubes import cat_flag, recv_flag
from pwnkit.lib.tubes import recv_pointer
from pwnkit.lib import stfp
from pwnkit.lib.log import plog


def get_base_name(_file):
    return os.path.basename(_file)


def get_func_name(_frame):
    return _frame.f_code.co_name


def dump_remote_binary(sh, output, prefix, suffix):
    sh.recvuntil(prefix, drop=True)
    data = sh.recvuntil(suffix, drop=True)
    open(output, "wb").write(data)
    return data


def get_salt():
    """ salt = get_salt() """
    return os.getenv("GDB_SALT") if (os.getenv("GDB_SALT")) else ""


def compile_symbol_file(src_file, salt="", arch=64):
    temp_file_name = "/tmp/gdb_symbols{}".format(salt)
    temp_file_path = f"{temp_file_name}.c"
    temp_so_path = f"{temp_file_name}.so"

    os.system(f"cp {src_file} {temp_file_path}")

    if arch == 64:
        payload = f"gcc -g -shared {temp_file_path} -o {temp_so_path}"
        os.system(payload)
    if arch == 32:
        payload = f"gcc -g -m32 -shared {temp_file_path} -o {temp_so_path}"
        os.system(payload)

    return f"{temp_so_path}"


def init_ssh_challenge(client: SFTPClient, challenge_dir, file_list):
    if not stfp.is_exists(client, challenge_dir):
        client.mkdir(challenge_dir)

    plog.waitfor(f"Uploading {file_list}")
    for local_path in file_list:
        remote_path = Path(challenge_dir) / local_path
        if stfp.is_exists(client, remote_path):
            continue
        client.put(local_path, str(remote_path))
        client.chmod(str(remote_path), os.stat(local_path).st_mode)


def get_current_time(fmt="%Y-%m-%d-%H-%M-%S"):
    # 默认格式化为 "年-月-日-时-分-秒"
    now = datetime.datetime.now()
    return now.strftime(fmt)
