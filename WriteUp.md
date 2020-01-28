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
 840:   55                      push   %rbp
 841:   48 89 e5                mov    %rsp,%rbp
 844:   48 83 ec 10             sub    $0x10,%rsp
 848:   48 89 7d f8             mov    %rdi,-0x8(%rbp)
 84c:   48 8b 45 f8             mov    -0x8(%rbp),%rax
 850:   48 8d 35 1d 01 00 00    lea    0x11d(%rip),%rsi        # 974 <_IO_stdin_used+0x4> (Offset dans le fichier : 0x974)
 857:   48 89 c7                mov    %rax,%rdi
 85a:   e8 71 fe ff ff          callq  6d0 <strcmp@plt> (Offset dans le fichier : 0x6d0)
 85f:   85 c0                   test   %eax,%eax
 861:   75 07                   jne    86a <is_valid+0x2a> (Offset dans le fichier : 0x86a)
 863:   b8 01 00 00 00          mov    $0x1,%eax
 868:   eb 05                   jmp    86f <is_valid+0x2f> (Offset dans le fichier : 0x86f)
 86a:   b8 00 00 00 00          mov    $0x0,%eax
 86f:   c9                      leaveq 
 870:   c3                      retq   

0000000000000871 <main> (Offset dans le fichier : 0x871):
main():
 871:   55                      push   %rbp
 872:   48 89 e5                mov    %rsp,%rbp
 875:   48 83 ec 10             sub    $0x10,%rsp
 879:   bf 00 01 00 00          mov    $0x100,%edi
 87e:   e8 5d fe ff ff          callq  6e0 <malloc@plt> (Offset dans le fichier : 0x6e0)
 883:   48 89 45 f8             mov    %rax,-0x8(%rbp)
 887:   48 8d 3d eb 00 00 00    lea    0xeb(%rip),%rdi        # 979 <_IO_stdin_used+0x9> (Offset dans le fichier : 0x979)
 88e:   b8 00 00 00 00          mov    $0x0,%eax
 893:   e8 28 fe ff ff          callq  6c0 <printf@plt> (Offset dans le fichier : 0x6c0)
 898:   48 8b 45 f8             mov    -0x8(%rbp),%rax
 89c:   48 89 c6                mov    %rax,%rsi
 89f:   48 8d 3d e9 00 00 00    lea    0xe9(%rip),%rdi        # 98f <_IO_stdin_used+0x1f> (Offset dans le fichier : 0x98f)
 8a6:   b8 00 00 00 00          mov    $0x0,%eax
 8ab:   e8 40 fe ff ff          callq  6f0 <__isoc99_scanf@plt> (Offset dans le fichier : 0x6f0)
 8b0:   48 8b 45 f8             mov    -0x8(%rbp),%rax
 8b4:   48 89 c7                mov    %rax,%rdi
 8b7:   e8 84 ff ff ff          callq  840 <is_valid> (Offset dans le fichier : 0x840)
 8bc:   85 c0                   test   %eax,%eax
 8be:   74 0e                   je     8ce <main+0x5d> (Offset dans le fichier : 0x8ce)
 8c0:   48 8d 3d cb 00 00 00    lea    0xcb(%rip),%rdi        # 992 <_IO_stdin_used+0x22> (Offset dans le fichier : 0x992)
 8c7:   e8 e4 fd ff ff          callq  6b0 <puts@plt> (Offset dans le fichier : 0x6b0)
 8cc:   eb 0c                   jmp    8da <main+0x69> (Offset dans le fichier : 0x8da)
 8ce:   48 8d 3d cd 00 00 00    lea    0xcd(%rip),%rdi        # 9a2 <_IO_stdin_used+0x32> (Offset dans le fichier : 0x9a2)
 8d5:   e8 d6 fd ff ff          callq  6b0 <puts@plt> (Offset dans le fichier : 0x6b0)
 8da:   48 8b 45 f8             mov    -0x8(%rbp),%rax
 8de:   48 89 c7                mov    %rax,%rdi
 8e1:   e8 ba fd ff ff          callq  6a0 <free@plt> (Offset dans le fichier : 0x6a0)
 8e6:   b8 00 00 00 00          mov    $0x0,%eax
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



#### iii) Patch

The patch consists on overwriting the `mov $0x0,%eax` into `mov $01,%eax`. In other words, we change only one byte at offset 2157 = 86a+3
`printf '\x01' | dd of=programNotPatched bs=1 seek=2157 count=1 conv=notrunc`

