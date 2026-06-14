![](./split-1781404709609.webp)
![](./split-1781404723965.webp)

in this problem we also have a way to overflow the buffer. However, the usefulFuntion does not read the flag as the previous challenge

![](./split-1781404806414.webp)

checking ROPgadgets, we acquire a way to manipulate rdi

![](./split-1781404855216.webp)

checking the binary memory, we find /bin/cat flag.txt, how convenient

![](./split-1781404892788.webp)

viewing hex data in ida grant us the exact address, given that the binary has no 