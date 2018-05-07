# Challenges

## Shop (200 points Pwning)

Since most of the writeups to this problem i've seen only contain bare Python code without any explanation what is going an, i decided to make my own writeup, with blackjack and hookers. We are given two files, namely shop and libc.so.6. The first thing to take away is, that it is very likely that we need the libc, meaning that there is a high chance of a vulnerability that lets us modify libc call addresses (most likely in the PLT, or a malloc hook or whatever).

First thing i did was load up the executable in gdb to check for any protections that are in place. With pwndbg installed, just type `checksec` to get the following output:


```
Arch: amd64-64-little
RELRO: Partial RELRO
Stack: Canary found
NX: NX enabled
PIE: No PIE (0x400000)
```

Stack canaries are found, an NX is enabled. But we see the executable is statically mapped to 0x400000, thats good to know for further investigation.

Now lets load the executable int IDA (or the disassembler of your choice). With a little bit of reversing, we can identify 4 major functionalities triggered by entering "c", "l", "n" or "a". Every other input rewards us with the `Command not recognized!` Message. Here is a simplyfied C code listing of the `main` function.


```c
while(1){
    get_input(&command_buffer,3)

    if(command_buffer == 'c')
        checkout();

    else if(command_buffer == 'l')
        list_items();

    else if(command_buffer == 'n')
        rename_shop();

    else if(command_buffer == 'a')
        add_item();

    else{
        puts("Command not recognized.")
    }
}
```

The function names are chosen to represent what they do. As we can see, there is no obvious way to delete items. We can just list them and rename the shop. Lets first look at the `list_items()` function. For the sake of readibility unnecessary information is omitted from all further code listings.


```c
Item* list_items()
{
for (Item* currItem = global_last_item; currItem; currItem = currItem->blink){
printf("%s: $".2f - %s\n", currItem->name, currItem->description, currItem->price)
}
}
```




I am good <sup>citation needed</sup>
