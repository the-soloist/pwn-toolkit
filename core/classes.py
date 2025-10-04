#!/usr/bin/env python
from pwnlib.tubes.ssh import ssh as SSH
from pwnlib.elf.elf import ELF


__all__ = [
    "ArgInfo",
    "ArgEnv",
    "EmptyClass",
]


class EmptyClass(object):
    def __repr__(self):
        class_name = self.__class__.__name__
        attributes = ", ".join(f"{name}={value}" for name, value in self.__dict__.items())
        return f"{class_name}({attributes})"


class ArgInfo(EmptyClass):
    def __init__(self):
        self.binary: ELF = None
        self.target: tuple = ()


class ArgEnv(EmptyClass):
    def __init__(self):
        self.cmd: list = []
        self.kwargs: dict = {}
        self.ssh: SSH = None
        self.workdir: str = "./"
