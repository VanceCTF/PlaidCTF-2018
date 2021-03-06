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

The function names are chosen to represent what they do. And as we can see, there is no obvious way to delete items, thus making a heap based exploit less likely<sup>[citation needed]</sup>. We can just list them and rename the shop.  Of course there is a bit of reversing necessary to come up with those names. My first guess for a vulnerability was the `get_input()` function, but the input is sanitized properly, so this was a dead end (that i am redacting from this writeup). First lets get a look at the `add_item()` (formerly known as `sub_400A5B()`) function to gain further knowledge of the layout of single items. 

```c
Item* add_item()
{
    char* buffer;
    if( dword_6021e8 <= 32 )
    {
        item_ptr = malloc(0x130);
        
        get_input(item_ptr + 0xC, 32)
        get_input(item_ptr + 0x2C, 256)
        get_input(buffer, 10)
        sscanf(buffer, "%f", item + 0x12C)
        
        sub_400986(item_ptr)
        *(QWORD*)item_ptr = qword_6021F0;
        qword_6021F0 = item_ptr;
        ++dword_6021E8;
    }
    else
        printf("Too many items.")
}
```

There is not much imagination needed to see that `dword_6021E8` holds the number of items added. When cross checking with how items are printed (in `list_items()`), we can see that `item_ptr + 0xC` is holds the name of the item, while `item_ptr + 0x2C` is the description and `item_ptr + 0x12C` stores the associated price. The value of `qword_6021F0` is saved in the newly allocated item at offset 0, and as the next step, the point of the current item is placed back in `qword_6021F0`. This suggests, that the items are stored in a linked list, and `qword_6021F0` holds the last item that was added to this list. But most importantly, this code listing shows one part of the vulnerability. `dword_6021e8` is checked for being 32 or lower, which means that we are able to add 33 items (classic "off by one")! That in itself is not a problem, but it will be later on.  But `sub_400986` looks suspicious, lets investigate further.

```c
sub_400986(Item* item_ptr)
{
    // fread from /dev/urandom into random_value
    for(int i = 0; i < 4; i++){
        *(BYTE*)(item_ptr+8 + i) = byte_602090[random_value % 0xF];
    }
}
```
With the buffer at `byte_602090` holding the string `0123456789abcdef` we can see, that four bytes at the offset + 8 are randomly selected from that string. Why that is the case is not clear at this point, but lets build the item definition from what we know so far.

```c
class Item{
    Item* blink; // Offset 0x0
    __int32 unknown; // Offset 0x8
    char* name; // Offset 0xC
    char* description; // Offset 0x2C
    float price; // Offset 0x12C
}
```

With this knowledge, lets keep going with the `rename_shop()` function.

```c
sub_400D6A()
{
    if( !qword_6021E0)
        qword_6021E0 = malloc(0x130);
    printf("Enter your shop name:");
    return get_input(qword_6021E0, 0x130);
}
```

`qword_6021E0` seems to be a global variable that is holding the pointer to the allocated buffer for the name of the shop. It is rather suspicious, that the shop name can be maximally 0x130 bytes long, which is exactly the size of one item! Now lets move on to the last function `checkout()`.

```c
sub_400B78()
{
    get_input(&haystack, 0x10004)
    currItem = qword_6021F0 // remember, this holds the item that was last added to the list!
    
    index = 0;
    
    while(currItem){
        if(memmem(&haystack, 0x10004, currItem->unknown, 0x4){
            qword_6020E0[index++] = currItem; // List of Items starts at qword_6020E0
        }
        currItem = currItem->blink;
    }
    
    total = 0.0;
    printf("%s Checkout in process...\n", qword_6021E0) // shop_name
    for(int i = 0; i < index; i++){
        printf("\tBuying %s for $%.2f\n",qword_6020E0[i]->name,qword_6020E0[i]->price) // qword_6020E0 = item_array
        total += qword_6020E0[i]->price;
    }
    printf("TOTAL: $%.2f\n", total);
}
```

First we are prompted to enter the haystack for `memmem`. If you are not familiar with `memmem`, i suggest you look it up. But this tells us the meaning of the previously unkown value in our Item definition. The four bytes are used as the needle to be found in the haystack. If the needle of the item in question is found in the haystack, it gets added to a global array of items at `qword_6020E0`. Now we recall the fact, that it is possible to add 33 items to our linked list. The while loop does not check, how many items are already added to the list. If we pass all the `memmem` calls, we can write at the position `qword_6020E0 + 0x8 * 0x20` which is the address `qword_6021E0` which looks familiar. It is the address where the pointer for the shop name is stored. So if we are able to pass the haystack checks for all 33 items, we can overwrite the pointer to our shop name, with a valid item. This process is shown by the following listings:

Before:
```
qword_6020E0 0
qword_6020E8 0
...
qword_6021D8 0
qword_6021E0 shop_name_ptr
```

After:
```
qword_6020E0 item_32_ptr
qword_6020E8 item_31_ptr
...
qword_6021D8 item_1_ptr
qword_6021E0 item_0_ptr
```

The `rename_shop()` function allows us to write arbitrary values to `item_0_ptr`. We found the vulnerability, but how do we use it effectively? If we modify the blink from the item stored at `qword_6021E0`, we can manually insert an element at the beginning of the list (since they are printed and evaluated in reverse order). But we have to be careful, because the items get traversed with `currItem = currItem->blink` the blink has to point at least to a readable memory area (or NULL to stop traversing the list). It is obvious to leak the address of libc first (because we are surely gonna need it later). Lets look at the PLT:

```
.got.plt:0000000000602000                 assume cs:_got_plt
.got.plt:0000000000602000                 ;org 602000h
.got.plt:0000000000602000                 dq ?
.got.plt:0000000000602008                 dq ?
.got.plt:0000000000602010                 dq 0
.got.plt:0000000000602018 off_602018      dq offset puts        
.got.plt:0000000000602020 off_602020      dq offset fread       
.got.plt:0000000000602028 off_602028      dq offset strlen     
.got.plt:0000000000602030 off_602030      dq offset __stack_chk_fail
.got.plt:0000000000602038 off_602038      dq offset setbuf        
.got.plt:0000000000602040 off_602040      dq offset printf        
.got.plt:0000000000602048 off_602048      dq offset __libc_start_main
.got.plt:0000000000602050 off_602050      dq offset fgets         
.got.plt:0000000000602058 off_602058      dq offset memmem        
.got.plt:0000000000602060 off_602060      dq offset malloc        
.got.plt:0000000000602068 off_602068      dq offset __isoc99_sscanf
.got.plt:0000000000602070 off_602070      dq offset fopen         
.got.plt:0000000000602078 off_602078      dq offset exit          
.got.plt:0000000000602078 _got_plt        ends
```

I decided to leak the address of `fread`. This left me two choices for a leak. I could let `fread` leak from the name or description field of the item. I just had to set up the item 0xC or 0x2C above the address of `fread`, respectively. I opted to leak it with the description field, so i needed my fake to be at `0x601FF4` ( + 0x2C = `0x602020`). This is easily done by renaming the shop so that following changes take effect:

Before:
```
item_0:

blink 0x0000000000000000
needle XXXX
name "Item_0"
description "Description_0"
value 1.0f
```

After:
```
item_0:

blink 0x0000000000601FF4
needle "1234"
name "Item_0"
description "Description_0"
value 1.0f
```

As you can see, i wrote the first 12 bytes of the item, so my blink would point to the address selected for the new fake item. In addition to that, i wrote the needle so it would be valid pattern (just to be sure). After that, we can trigger the "l" command, and the last item listed will contain the address of `fread` in the description field. So we got our libc address, success. The next step is to do something with the information that we extracted.


