#!/usr/bin/env python
# -*- coding: utf-8 -*-

import stat
from paramiko import SFTPClient


def is_exists(sftp_client: SFTPClient, path):
    try:
        return sftp_client.stat(path)
    except:
        return False


def is_file(sftp_client: SFTPClient, path):
    try:
        file_attr = is_exists(sftp_client, path)
        return stat.S_ISREG(file_attr.st_mode)
    except:
        return False


def is_dir(sftp_client: SFTPClient, path):
    try:
        file_attr = is_exists(sftp_client, path)
        return stat.S_ISDIR(file_attr.st_mode)
    except:
        return False
