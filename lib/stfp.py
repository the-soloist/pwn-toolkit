#!/usr/bin/env python

import stat
from paramiko import SFTPClient
from pathlib import Path
from pwn import log


def is_exists(sftp_client: SFTPClient, path: str | Path):
    if isinstance(path, Path):
        path = str(path)

    try:
        return sftp_client.stat(path)
    except Exception as e:
        return False


def is_file(sftp_client: SFTPClient, path: str | Path):
    if isinstance(path, Path):
        path = str(path)

    file_attr = is_exists(sftp_client, path)
    return file_attr and stat.S_ISREG(file_attr.st_mode)


def is_dir(sftp_client: SFTPClient, path: str | Path):
    if isinstance(path, Path):
        path = str(path)

    file_attr = is_exists(sftp_client, path)
    return file_attr and stat.S_ISDIR(file_attr.st_mode)
