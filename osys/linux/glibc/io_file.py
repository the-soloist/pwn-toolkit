#!/usr/bin/env python
# -*- coding: utf-8 -*-
# reference:
#   - https://github.com/ray-cp/pwn_debug/blob/master/pwn_debug/IO_FILE_plus.py
#   - https://github.com/RoderickChan/pwncli/blob/main/pwncli/utils/io_file.py

from pwn import FileStructure, hexdump, variables


class IO_FILE_plus(FileStructure):
    def hexdump(self):
        print(hexdump(bytes(self)))

    def house_of_pig(self):
        pass

    def house_of_apple2(self):
        pass

    def house_of_apple3(self):
        pass


class IO_jump_t(dict):
    pass
