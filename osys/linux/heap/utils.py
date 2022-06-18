#!/usr/bin/env python
# -*- coding: utf-8 -*-


def safe_link(pos, ptr, first=False):
    """
    for glibc 2.32
        encode a given safe link into its original pointer
    """
    if first is True:
        return pos ^ ptr
    else:
        return (pos >> 12) ^ ptr


def unsafe_link(obfus_ptr):
    """
    for glibc 2.32 
        decode a given safe link into its original pointer

    ref:
        - https://github.com/x64x6a/ctf-writeups/blob/master/PlaidCTF_2021/pwnable/plaidflix/solve.py#L12
        - https://gist.github.com/hkraw/0576a28c5436734d0fbe6d8ddd378143#file-plaidctf-plaidflix-py-L8
        - https://github.com/MaherAzzouzi/LinuxExploitation/blob/master/PlaidCTF-plaidflix/solve.py#L83
    """
    o2 = (obfus_ptr >> 12) ^ obfus_ptr
    return (o2 >> 24) ^ o2
