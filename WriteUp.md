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



#### iii) Patch

The patch consists in overwriting the `mov $0x0,%eax` into `mov $01,%eax`. In other words, we change only one byte at offset 2157 = 86a+3
`printf '\x01' | dd of=programNotPatched bs=1 seek=2157 count=1 conv=notrunc`

```asm
 86a:   b8 00 00 01 00          mov    $0x10000,%eax
```

> Notice: to do the same as dd with [ghidra](https://ghidra-sre.org/), we can use context menu and click on `patch instruction`


## B- Questions

- What are the possible attack paths on the signature of an embedded system ?
> Compared with services such as servers, softwares, cloud ..., attackers could have access to the embedded system physically. 
> For example he can retrieve the hard-codded signature (private/public) keys from the silica, he can use Man In the Middle in order to fake server authentication and read all the communication. 
> Moreover due to low memory and energy consumption limits, used algorithm to cipher are not strong enough and random generators to seed initialisation vectors are often predictable. 

- A quoi sert la chaine de confiance? Pourquoi est-elle nécessaire?
- Décrire la méthode pour aborder la sécurité sur un produit embarqué. Pourquoi établir un modèle d'attaquant est-il important?
> Produit/service ; Modèle de l'attaquant ; Flots d'information

- Trouver un moyen rapide de faire du debug embarqué (par exemple sur cible ARM)? Expliquer les avantages
> JTAG ; emulation ; qemu ...


- Lister les catégories de bug possibles et comment les exploiter et les défendre
> Buffers overflow ; 

- Quelles idées pour améliorer la sécurité en embarqué? (IA, Anti-debug, Obfuscation, Crypto ...) Choisissez une idée, chercher si elle existe et développer en quelques phrases quel avantage elle apporte et ses limites
> 
