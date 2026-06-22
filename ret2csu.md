![](./ret2csu-1782142784949.webp)

the win function exist in the plt section, which mean that we can call it directly in our chain

![](./ret2csu-1782142765106.webp)

unfortunately, ret2win check for rdi, rsi and rdx for specific values

![](./ret2csu-1782142735031.webp)

now we dont exactly have those convenient gadget to manipulate registers

![](./ret2csu-1782142948599.webp)

searching the binary using objdump, we discover our necessary aparatus
