![](img/Putsception%20Hard-1781945098796.webp)

we got no output this challenge, rough start

knowing libc is the target, we can ultilise got table (which is always available no matter if pie exist) to leak libc_base

some functions such as puts, possess an entry on the got table that points to its address in libc, which net us the libc_base. With that, the problem should be a cake walk

the chain is: leaking libc by printing the address as puts(got table)