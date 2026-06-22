![](./callme-1782095019148.webp)

there exist three "callme" function in this binary

![](./callme-1782095099811.webp)

upon inspection in gdb, it seems that those call me function check for rdi, rsi, rdx for specific values and each print out part of the flag

![](./callme-1782095178540.webp)

paired with the fact that there is no pie, building a rop chain should be easy enough