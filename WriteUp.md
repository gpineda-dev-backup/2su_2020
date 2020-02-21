# INSA - 2su : IoT security WriteUp

## A- Crack Emily


#### i) Introduction
Let's following the awesome [Emily's tutorial](https://archive.emily.st/2015/01/27/reverse-engineering/) to understand basis of reverse engineering with a simple c program   which check if the user input is a valid password or not.

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int is_valid(const char* password) {
    if (strcmp(password, "poop") == 0) { //valid password
        return 1;
    } else {
        return 0;
    }
}

int main()
{
    char* input = malloc(256);
    printf("Please input a word: ");
    scanf("%s", input);

    if (is_valid(input)) {
        printf("That's correct!\n");
    } else {
        printf("That's not correct!\n");
    }

    free(input);
    return 0;
}

```

#### ii) Analysis

By searching for more information about the file, we find it is a binary ELF for x86-64 architecture.
```bash
user@optiplex-1504:~/Documents/securiteIOT$ file program 
program: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d1beda1d94a34542f2f73cf19d185bf96a671f0d, not stripped
```

We can start by looking for strings into the compiled binary, see above the output. 
```bash
$ strings program | less

AWAVA
AUATL
[]A\A]A^A_
poop
Please input a word: 
That's correct!
That's not correct!
;*3$"

```

Let's now understand what the code is doing, so by using `objdump -S -l -C -F -t -w program` we get 

```asm

0000000000000840 <is_valid> (Offset dans le fichier : 0x840):
is_valid():
 ...
 861:   75 07                   jne    86a <is_valid+0x2a> (Offset dans le fichier : 0x86a)
 863:   b8 01 00 00 00          mov    $0x1,%eax
 868:   eb 05                   jmp    86f <is_valid+0x2f> (Offset dans le fichier : 0x86f)
 86a:   b8 00 00 00 00          mov    $0x0,%eax
 86f:   c9                      leaveq 
 870:   c3                      retq   

0000000000000871 <main> (Offset dans le fichier : 0x871):
main():
       ...

 8ab:   e8 40 fe ff ff          callq  6f0 <__isoc99_scanf@plt> (Offset dans le fichier : 0x6f0)
 8b0:   48 8b 45 f8             mov    -0x8(%rbp),%rax
 8b4:   48 89 c7                mov    %rax,%rdi
 8b7:   e8 84 ff ff ff          callq  840 <is_valid> (Offset dans le fichier : 0x840)

       ...
 8eb:   c9                      leaveq 
 8ec:   c3                      retq   
 8ed:   0f 1f 00                nopl   (%rax)

```
The asm code provides indications about the code flow. 
* In binary offset 8b7, is_valid function is called from `main`
* In binary offset 840, `is_valid` function is defined.
* In binary offset 85a, a comparison is done `strcmp`
* Few lines after, the if statement is done 861, 868

Our goal is to return 1 on is_valid whatever the user's input. the returned value is prepared with `mov    $0x1,%eax` (move 1 into %eax) and `mov    $0x0,%eax`(move 0 into %eax => is_valid = 0). 

https://unix.stackexchange.com/questions/214820/patching-a-binary-with-dd/214824

#### iii) Patch

The patch consists in overwriting the `mov $0x0,%eax` into `mov $01,%eax`. In other words, we change only one byte at offset 2157 = 86a+3
`printf '\x01' | dd of=programNotPatched bs=1 seek=2157 count=1 conv=notrunc`

```asm
 86a:   b8 00 00 01 00          mov    $0x10000,%eax
```

> Notice: to do the same as dd with [ghidra](https://ghidra-sre.org/), we can use context menu and click on `patch instruction`



### ls' turn
> Have a look at disassembled /sbin/ls by Ghidra


## B- Questions

- What are the possible attack paths on the signature of an embedded system ?
> Compared with services such as servers, softwares, cloud ..., attackers could have access to the embedded system physically. 
> For example he can retrieve the hard-codded signature (private/public) keys from the silica, he can use Man In the Middle in order to fake server authentication and read all the communication. 
> Moreover due to low memory and energy consumption limits, used algorithm to cipher are not strong enough and random generators to seed initialisation vectors are often predictable. 

- What is the chain of trust for? Why is it necessary?
> Such a chain allows to target possible points of failure / attacks in the device process. As keystone, it is relevant to protect these points for example with Devops flow
> (check source code weaknesses, build and dynamic tests), channels of communication medium (radio protection (short range transmission, frames ciphering, protocols...), protection of the third tiers (server, authentication)) and physical control (protect against physical hack, sniffing, ...).   
> Anyway through an evaluation of risks and impacts, we can score the relevancy of such attack.   
- Describe the method for approaching security on an embedded product. Why is establishing an attacker model important?
> First identify if the solution is a product or a service, then establish the attacker model to adapt security with some counter-measures. An other point of failure is the data flow, indeed.

- Find a quick way to do embedded debugging (for example on ARM target)? Explain the benefits
> First it is more confortable for a dev to code on his computer (more tools, GUI, IDEs ..). At this time, using emulator such as qemu allow to compile and execute faslty without uploading the firmware on the device. Because of emulation, the computer has to do architecture translation (arm, x86, risc ..), making more slowly the execution than into real device.    
> Moreover JTAG can be used for debugging directly while executing on embedded system, but pay attention to deactivate dev functions for the production stage.


- List possible bug categories and how to exploit and defend them
> Buffers overflow ; 

- What ideas to improve on-board security? (AI, Anti-debug, Obfuscation, Crypto ...) Choose an idea, search if it exists and develop in a few sentences what advantage it brings and its limits exploit and defend them
> Devops, industrial processing, remote debugging... https://github.com/aws/aws-fpga ; 
> Because i'm interested in devops' processing, let's have a look at solutions to enhance iot security. The first step is to reduce bugs mainly thanks to log reporting and the key is centralisation. I think cloud's architecture could help to remotely debug devices and with OTA's updates (Over the Air) ensure security concerns fastly.
> Let's focus on running tests for the iot ; indeed the use of cloud to build and compute on real devices most of the tests will reduce bugs and by the way security issues. 
> As example I applied my last internship at equensWorldline with a team working on strong authentication for mobile solutions ; they use an opensource platform openstf to manage and deploy applications on remote Android devices. Using such a platform instead of emulators the observed behoviour is more faithful with the realworld.

> Here let's me introduce yourself a similary solution for FPGAs (Field Programmable Gate Array) available from the Amazon Cloud platform where you can [rent instances](https://aws.amazon.com/fr/ec2/instance-types/f1/). Giving the opportunity to access such expensive devices to run tests should contribute to generalise good practices and enhance the chain of trust.

## C- Where is tux ?

### 0- Run the code
After downloading the firmware image `vmlinuz-qemu-arm-2.6.20`, we can start it with Qemu (ARM arch)
```bash
$ qemu-system-arm -M versatilepb -m 16 -kernel vmlinuz-qemu-arm-2.6.20-orinal -append "clocksource=pit quiet rw"
```

Into the VM, pay attention to the `qwerty` keyboard to execute:
```bash
$ run_demo
```

Then, you will be tux everywhere in the foreground.

### 1- Let's find where our friend is hidden ...
By using `binwalk` tool, we can analyse the firmware content (-Me for recursive mode). We are looking for a png type, so the option `-dd "png image:png"` can help to filter results.

```bash
$ binwalk -MeD "png image:png" vmlinuz-qemu-arm-2.6.20-original

Scan Time:     2020-02-14 12:42:22
Target File:   /home/user/Téléchargements/vmlinuz-qemu-arm-2.6.20-orinal
MD5 Checksum:  5c8a1c2f291db79915eb2fb0eda1ebbe
Signatures:    396

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Linux kernel ARM boot executable zImage (little-endian)
12720         0x31B0          gzip compressed data, maximum compression, from Unix, last modified: 2007-05-09 06:03:48


Scan Time:     2020-02-14 12:42:23
Target File:   /home/user/Téléchargements/_vmlinuz-qemu-arm-2.6.20-orinal-4.extracted/31B0
MD5 Checksum:  00f36d76c384709b0a6ca5cb93e25c0e
Signatures:    396

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
58971         0xE65B          LZMA compressed data, properties: 0xC0, dictionary size: 0 bytes, uncompressed size: 3223117372 bytes
59360         0xE7E0          gzip compressed data, maximum compression, from Unix, last modified: 2007-05-09 06:02:29
1851243       0x1C3F6B        LZMA compressed data, properties: 0x64, dictionary size: 0 bytes, uncompressed size: 51539607552 bytes
[..]
2562660       0x271A64        CRC32 polynomial table, little endian

[..]

Scan Time:     2020-02-14 12:42:26
Target File:   /home/user/Téléchargements/_vmlinuz-qemu-arm-2.6.20-orinal-4.extracted/_31B0.extracted/E7E0
MD5 Checksum:  a87565b1913f211274dd18653451483c
Signatures:    396

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
[..]
2984412       0x2D89DC        ASCII cpio archive (SVR4 with no CRC), file name: "/usr/local/share/directfb-examples/tux.png", file name length: "0x0000002B", file size: "0x00006050"
3009224       0x2DEAC8        ASCII cpio archive (SVR4 with no CRC), file name: "/usr/local/share/directfb-examples/wood_andi.jpg", file name length: "0x00000031", file size: "0x0000F327"


[..]

```

Here we can see the path to our friend : `/usr/local/share/directfb-examples/tux.png` at offset `0x2D89DC` of the gzip content: `0xE7E0` 

#### a) The noob way
By executing the last command with binwalk, a folder `__vmlinuz-qemu-arm-2.6.20-orinal.extracted` has been created.    
Here we can find : `_31B0.extracted/_E7E0.extracted`  and the image file : `/home/user/Téléchargements/_vmlinuz-qemu-arm-2.6.20-orinal-4.extracted/_31B0.extracted/_E7E0.extracted/cpio-root/usr/local/share/directfb-examples/tux.png`

#### b) The hard way
The idea is to walk into the firmware to identify offsets and extract content with `dd`.   

```bash
$ binwalk ./vmlinuz-qemu-arm-2.6.20-orinal 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Linux kernel ARM boot executable zImage (little-endian)
12720         0x31B0          gzip compressed data, maximum compression, from Unix, last modified: 2007-05-09 06:03:48
```

Let's extract and unzip the gzip compressed data located at offset `0x31B0`.
```
$ dd if=vmlinuz-qemu-arm-2.6.20-orinal of=31B0.gz bs=1 skip=$((0x31B0))
$ gunzip 31B0.gz

$ binwalk 31B0

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
58971         0xE65B          LZMA compressed data, properties: 0xC0, dictionary size: 0 bytes, uncompressed size: 3223117372 bytes
59360         0xE7E0          gzip compressed data, maximum compression, from Unix, last modified: 2007-05-09 06:02:29
[...]
2562660       0x271A64        CRC32 polynomial table, little endian
[...]
```

Then, do the same with the compressed data located at offset `0xE7E0`
```bash
$ dd if=31B0 of=e7e0.gz skip=$((0xE7E0)) bs=1 count=$(( $((0x1C3F6B)) - $((0xE7E0)) +1  ))
$ file e7e0.gz
e7e0.gz: gzip compressed data, last modified: Wed May  9 06:02:29 2007, max compression, from Unix

$ gunzip e7e0.gz
$ file e7e0
e7e0: ASCII cpio archive (SVR4 with no CRC)

$ binwalk e7e0 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
[..]
2984412       0x2D89DC        ASCII cpio archive (SVR4 with no CRC), file name: "/usr/local/share/directfb-examples/tux.png", file name length: "0x0000002B", file size: "0x00006050"
3009224       0x2DEAC8        ASCII cpio archive (SVR4 with no CRC), file name: "/usr/local/share/directfb-examples/wood_andi.jpg", file name length: "0x00000031", file size: "0x0000F327"
[..]

```

To finish, we can extract the cpio archive

```bash
$ dd if=e7e0 of=tux-cpio bs=1 skip=$((0x2D89DC)) count=$(( $((0x2DEAC8 )) - $((0x2D89DC )) +1  ))
$ file tux-cpio
tux-cpio: ASCII cpio archive (SVR4 with no CRC)
```

And sync with our local fs:
```bash
$ cpio --make-directories -i -F tux-cpio
$ gimp /usr/local/share/directfb-examples/tux.png
```

Here is the win !

find . -iname *.c -print | cpio -ov >/tmp/c_files.cpio


### 2- Repack our new Tux
First, with cpio we recreate a well formated object (`H newc` for SVR4 without CRC format)
```bash
$ find /usr/local/share/directfb-examples/tux.png | cpio -o -H newc > ./ntux-cpio
$ file ntux-cpio
ntux-cpio: ASCII cpio archive (SVR4 with no CRC)
```

And replace in the main cpio archive at 0xe7e0 (patch and compress)

```bash
$ dd if=ntux-cpio of=e7e0 seek=$((0x2D89DC)) bs=1 conv=notrunc count=$(( $((0x2DEAC8 )) - $((0x2D89DC )) +1  ))
$ gzip e7e0
$ file e7e0.gz
e7e0.gz: gzip compressed data, was "e7e0", last modified: Fri Feb 14 14:15:38 2020, from Unix
```


```bash
$ dd if=e7e0.gz of=31B0 seek=$(( 0xe7e0 )) count=$(( $(( 0x1C3F6B )) - $(( 0xe7e0 )) )) bs=1
$ gzip 31B0
$ file 31B0.gz
31B0.gz: gzip compressed data, was "31B0", last modified: Fri Feb 14 14:22:09 2020, from Unix
```

```bash
$ dd if=31B0.gz of=vmlinuz-qemu-arm-2.6.20-hacked seek=$((0x31b0)) bs=1

$ binwalk -e vmlinuz-qemu-arm-2.6.20-hacked 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Linux kernel ARM boot executable zImage (little-endian)
12720         0x31B0          gzip compressed data, has original file name: "31B0", from Unix, last modified: 2020-02-14 14:22:09
```

Let's test out repacked firmware image...
```bash
$ qemu-system-arm -M versatilepb -m 16 -kernel vmlinuz-qemu-arm-2.6.20-hacked -append "clocksource=pit quiet rw"
pulseaudio: set_sink_input_volume() failed
pulseaudio: Reason: Invalid argument
pulseaudio: set_sink_input_mute() failed
pulseaudio: Reason: Invalid argument
```
Unfortunately qemu stucks into black screen, In fact I suppose that it is due to a checksum issue. We should recalculate the CRC32 table after modifying our binary !


00100760
00100760

0804848b
