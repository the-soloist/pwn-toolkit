#!/usr/bin/env python
# -*- coding: utf-8 -*-


def protect_ptr(pos, ptr):
    return (pos >> 12) ^ ptr


def reveal_ptr(ptr):
    """
    hex(protect_ptr(0x55a6fbda92e0, 0x55a6fbda92a0)) == 0x55a3a1b52f09

         o2 =    (0x55a|6fbda9 ^ 
                     0x|55a6fb) ^ 
              (0x55a6fb|da92e0 ^ 
                  0x55a|6fbda9)
    ==>  o2 =  0x55a6fb|(da92e0^55a6fb)
    ==>  o2 >> 24 == 0x55a6fb
    """

    o2 = (ptr >> 12) ^ ptr  # 恢复高3字节 0xAAAXXXAAAAAA
    return (o2 >> 24) ^ o2  # 恢复低3字节 0xAAABBBXXXXXX
