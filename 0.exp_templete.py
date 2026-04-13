from pwn import *
context(arch="amd64", os="linux", terminal=["tmux", "splitw", "-h"])
context.binary = "./pwn"


if len(args) == 1:
    p = process(context.binary.path)
    context.log_level = "debug"
else:
    HOST = args[1]
    PORT = int(args[2])
    p = remote(HOST, PORT)
    context.log_level = "info"


elf = ELF(context.binary.path)
# libc = ELF("libc.so.6") 


p.interactive()



# auto get flag
print("Trying to get flag...")
p.sendline("cat /flag")
flag = p.recvline()
if flag:
    print("FOUND FLAG: ", flag.decode())
