#!/usr/bin/env python

from pwn import FileStructure, context, hexdump, log

__all__ = [
    "IO_FILE_plus",
]


length = 0
size = "size"
name = "name"


class IO_FILE_plus(FileStructure):

    variables = {
        0: {name: "flags", size: length},
        1: {name: "_IO_read_ptr", size: length},
        2: {name: "_IO_read_end", size: length},
        3: {name: "_IO_read_base", size: length},
        4: {name: "_IO_write_base", size: length},
        5: {name: "_IO_write_ptr", size: length},
        6: {name: "_IO_write_end", size: length},
        7: {name: "_IO_buf_base", size: length},
        8: {name: "_IO_buf_end", size: length},
        9: {name: "_IO_save_base", size: length},
        10: {name: "_IO_backup_base", size: length},
        11: {name: "_IO_save_end", size: length},
        12: {name: "markers", size: length},
        13: {name: "chain", size: length},
        14: {name: "fileno", size: 4},
        15: {name: "_flags2", size: 4},
        16: {name: "_old_offset", size: length},
        17: {name: "_cur_column", size: 2},
        18: {name: "_vtable_offset", size: 1},
        19: {name: "_shortbuf", size: 1},
        20: {name: "unknown1", size: -4},
        21: {name: "_lock", size: length},
        22: {name: "_offset", size: 8},
        23: {name: "_codecvt", size: length},
        24: {name: "_wide_data", size: length},
        25: {name: "_freeres_list", size: length},
        26: {name: "_freeres_buf", size: length},
        27: {name: "__pad5", size: length},
        28: {name: "_mode", size: 4},
        29: {name: "_unused2", size: length},
        30: {name: "vtable", size: length},
    }

    def __init__(self, null=0):
        self.vars_ = [self.variables[i]["name"] for i in sorted(self.variables.keys())]
        self.setdefault(null)
        self.length = self.update_var(context.bytes)
        self._old_offset = (1 << context.bits) - 1

    def __setattr__(self, item, value):
        if item == "_IO_FILE_plus__pad5":  # why ???
            item = "__pad5"
        if item in FileStructure.__dict__ or item in self.vars_:
            object.__setattr__(self, item, value)
        else:
            log.error("Unknown variable %r" % item)

    def __getattr__(self, item):
        if item in FileStructure.__dict__ or item in self.vars_:
            return object.__getattribute__(self, item)
        log.error("Unknown variable %r" % item)

    def __repr__(self):
        structure = []
        for i in self.vars_:
            structure.append(" %s: %s" % (i, hex(self.__getattr__(i))))
        return "{" + ",\n".join(structure) + "}"

    def setdefault(self, null):
        self.flags = 0
        self._IO_read_ptr = 0
        self._IO_read_end = 0
        self._IO_read_base = 0
        self._IO_write_base = 0
        self._IO_write_ptr = 0
        self._IO_write_end = 0
        self._IO_buf_base = 0
        self._IO_buf_end = 0
        self._IO_save_base = 0
        self._IO_backup_base = 0
        self._IO_save_end = 0
        self.markers = 0
        self.chain = 0
        self.fileno = 0
        self._flags2 = 0
        self._old_offset = 0
        self._cur_column = 0
        self._vtable_offset = 0
        self._shortbuf = 0
        self.unknown1 = 0
        self._lock = null
        self._offset = 0xffffffffffffffff
        self._codecvt = 0
        self._wide_data = null
        self._freeres_list = 0
        self._freeres_buf = 0
        self.__pad5 = 0
        self._mode = 0
        self._unused2 = 0
        self.vtable = 0

    def update_var(self, l):
        var = {}
        for i in self.variables:
            var[self.variables[i]["name"]] = self.variables[i]["size"]
        for i in var:
            if var[i] <= 0:
                var[i] += l
        if l == 4:
            var["_unused2"] = 40
        else:
            var["_unused2"] = 20
        return var

    def offset(self):
        pos = 0
        for k, v in self.length.items():
            print(f"{hex(pos)}: {k}")
            pos += v

    def hexdump(self):
        print(hexdump(bytes(self)))

    def house_of_pig(self):
        pass

    def house_of_apple2(self):
        pass

    def house_of_apple3(self):
        pass
