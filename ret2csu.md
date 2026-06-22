![](./ret2csu-1782142784949.webp)

the win function exist in the plt section, which mean that we can call it directly in our chain

![](./ret2csu-1782142765106.webp)

unfortunately, ret2win check for rdi, rsi and rdx for specific values

![](./ret2csu-1782142735031.webp)

now we dont exactly have those convenient gadget to manipulate rdx

![](./ret2csu-1782142948599.webp)

searching the binary using objdump, we discover our necessary apparatus

now, the tricky part is dealing with call |r12+rbx * 8|

our candidates exist in the plt sections, which are pwnme and ret2win

![](./ret2csu-1782143093343.webp)

![](./ret2csu-1782143132302.webp)

bad news! pwnme modify rdx while ret2win exit, breaking the program

that left us with one hope: looking in the data section of the binary for some lucky finds

![](./ret2csu-1782143352254.webp)

with patient, we find a perfect candidate, which is a gadget that does absolutely nothing and return