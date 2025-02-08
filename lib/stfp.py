#!/usr/bin/env python
# -*- coding: utf-8 -*-

import stat
from paramiko import SFTPClient
from pwn import log


def is_exists(sftp_client: SFTPClient, path):
    try:
        return sftp_client.stat(path)
    except Exception as e:
        log.error(f"error: {e}")   
        return False


def is_file(sftp_client: SFTPClient, path):
    file_attr = is_exists(sftp_client, path)
    return file_attr and stat.S_ISREG(file_attr.st_mode)


def is_dir(sftp_client: SFTPClient, path):
    file_attr = is_exists(sftp_client, path)
    return file_attr and stat.S_ISDIR(file_attr.st_mode)
