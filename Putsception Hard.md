![](img/Putsception%20Hard-1781945098796.webp)

we got no output this challenge, rough start

knowing libc is the target, we can ultilise got table (which is always available no matter if pie exist) to leak libc_base

some functions such as puts, have a got table that point to its address in libc,