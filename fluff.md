
now this is a hard one

![](./fluff-1782130394835.webp)

we are provided with no convenient gadgets for altering a memory space

instead we are provided with some peculiar gadgets as of below

![](./fluff-1782130493030.webp)

bextr rdx,rcx,rbx let us provide rbx an arbitary value, while xlat let us manipulate al with rbx and stos al,es:(rdi) let us store a single byte from al to the memory at rdi

all left to do is find every single byte we need in the binary to craft the flag address, one byte at a time. How rigorous!

```

```