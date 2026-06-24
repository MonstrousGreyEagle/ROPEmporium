just like [callme](../x86_64/callme.md), this cjhallenge involve calling three functions to obtain the flag

in x86_32, function take arguments from the stack instead of from registers, and each call require some way to clear the stack as the functions itself doesnt clear its arguments 

![](./callme32-1782295407666.webp)

![](./callme32-1782295424868.webp)

![](./callme32-1782295455671.webp)

with ROPgadget provid