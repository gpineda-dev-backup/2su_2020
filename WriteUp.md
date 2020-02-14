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
```c

/* WARNING: Could not reconcile some variable overlaps */

char * FUN_00111540(char *param_1,long param_2,char *param_3,tm *param_4,byte param_5,
                   undefined8 param_6,undefined8 param_7,uint param_8)

{
  int iVar1;
  long lVar2;
  bool bVar3;
  byte bVar4;
  char cVar5;
  int iVar6;
  char *__s;
  char *__dest;
  ulong uVar7;
  long lVar8;
  ulong uVar9;
  char *pcVar10;
  char cVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  int iVar15;
  ulong __n;
  uint uVar16;
  size_t __n_00;
  size_t __n_01;
  int iVar17;
  int iVar18;
  ulong uVar19;
  long lVar20;
  bool bVar21;
  char cVar22;
  int iVar23;
  char *__n_02;
  char *__dest_00;
  char *__dest_01;
  char *pcVar24;
  char cVar25;
  long in_FS_OFFSET;
  bool bVar26;
  uint local_50c;
  ulong local_4c8;
  uint local_4c0;
  uint local_4b8;
  uint local_4b0;
  undefined8 local_498;
  undefined8 local_490;
  undefined8 local_488;
  undefined8 local_480;
  undefined8 local_478;
  long local_470;
  char *local_468;
  char local_458;
  undefined local_457;
  char local_456;
  char acStack1109 [13];
  char local_448;
  char local_447 [22];
  char acStack1073 [1009];
  long local_40;
  
  uVar16 = param_4->tm_hour;
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  __s = "";
  if (param_4->tm_zone != (char *)0x0) {
    __s = param_4->tm_zone;
  }
  if ((int)uVar16 < 0xd) {
    local_50c = 0xc;
    if (uVar16 != 0) {
      local_50c = uVar16;
    }
  }
  else {
    local_50c = uVar16 - 0xc;
  }
  cVar5 = *param_3;
  pcVar24 = (char *)0x0;
  if (cVar5 == '\0') {
LAB_00111874:
    if ((param_1 != (char *)0x0) && (param_2 != 0)) {
      *param_1 = '\0';
    }
LAB_00111763:
    if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    return pcVar24;
  }
LAB_00111640:
  if (cVar5 == '%') {
    __n = (ulong)param_5;
    cVar5 = '\0';
    local_4b0 = 0;
    do {
      local_4c0 = local_4b0;
      cVar22 = (char)__n;
      param_3 = param_3 + 1;
      cVar25 = *param_3;
      cVar11 = cVar25 + -0x30;
      bVar26 = cVar25 == '0';
      while (local_4b0 = SEXT14(cVar25), !bVar26) {
        uVar7 = (ulong)local_4b0;
        if (!bVar26 && SBORROW1(cVar25,'0') == cVar11 < '\0') {
          if (cVar25 == '^') {
            __n = 1;
            local_4b0 = local_4c0;
          }
          else {
            if (cVar25 != '_') {
LAB_001116a4:
              uVar16 = 0xffffffff;
              if (9 < local_4b0 - 0x30) goto LAB_00111710;
              uVar16 = 0;
              goto LAB_001116e1;
            }
          }
          break;
        }
        if (cVar25 != '#') {
          if (cVar25 != '-') goto LAB_001116a4;
          break;
        }
        param_3 = param_3 + 1;
        cVar25 = *param_3;
        cVar5 = '\x01';
        cVar11 = cVar25 + -0x30;
        bVar26 = cVar11 == '\0';
      }
    } while( true );
  }
  if (1 < (ulong)(param_2 - (long)pcVar24)) {
    if (param_1 != (char *)0x0) {
      *param_1 = cVar5;
      param_1 = param_1 + 1;
    }
    pcVar24 = pcVar24 + 1;
    goto LAB_0011162d;
  }
  goto LAB_00111760;
LAB_001116e1:
  do {
    if ((int)uVar16 < 0xccccccd) {
      if ((uVar16 == 0xccccccc) && ('7' < *param_3)) goto LAB_001116e9;
      uVar16 = (int)*param_3 + -0x30 + uVar16 * 10;
    }
    else {
LAB_001116e9:
      local_4b0 = SEXT14(param_3[1]);
      param_3 = param_3 + 1;
      uVar7 = (ulong)local_4b0;
      if (9 < local_4b0 - 0x30) {
        uVar16 = 0x7fffffff;
        break;
      }
      uVar16 = 0x7fffffff;
    }
    local_4b0 = SEXT14(param_3[1]);
    param_3 = param_3 + 1;
    uVar7 = (ulong)local_4b0;
  } while (local_4b0 - 0x30 < 10);
LAB_00111710:
  cVar25 = (char)local_4b0;
  local_4c8._0_1_ = (char)uVar7;
  __dest = &local_456;
  __dest_00 = param_1;
  uVar13 = local_50c;
  if (((char)local_4c8 == 'E') || ((char)local_4c8 == 'O')) {
    cVar11 = param_3[1];
    param_3 = param_3 + 1;
    __n_02 = param_3;
    uVar12 = local_4b0;
    switch(cVar11) {
    case '\0':
      goto switchD_001117b4_caseD_0;
    case '%':
      if (local_4b0 == 0) goto switchD_00111734_caseD_25;
      goto LAB_00111a10;
    case ':':
      local_4c8._0_1_ = ':';
      goto LAB_0011213f;
    case 'A':
      if (local_4b0 == 0) goto switchD_00111734_caseD_41;
      break;
    case 'B':
      if (local_4b0 == 0) goto switchD_00111734_caseD_42;
      break;
    case 'C':
      local_4c8._0_1_ = 'C';
      if (local_4b0 != 0x45) goto LAB_001127c3;
      local_4c8._0_1_ = 'C';
      local_4b0 = 0;
      cVar5 = 'E';
      goto LAB_0011210e;
    case 'D':
      if (local_4b0 == 0) goto LAB_001127a5;
      break;
    case 'F':
      if (local_4b0 == 0) goto LAB_001124c2;
      break;
    case 'G':
    case 'V':
    case 'g':
      local_4c8._0_1_ = cVar11;
      if (local_4b0 != 0x45) goto LAB_0011235d;
      break;
    case 'H':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'H';
        goto LAB_0011234d;
      }
      break;
    case 'I':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'I';
        goto LAB_0011232b;
      }
      break;
    case 'M':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'M';
        goto LAB_0011231b;
      }
      break;
    case 'N':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'N';
        goto LAB_0011229b;
      }
      break;
    case 'P':
      goto switchD_001117b4_caseD_50;
    case 'R':
      goto switchD_001117b4_caseD_52;
    case 'S':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'S';
        goto LAB_0011228f;
      }
      break;
    case 'T':
      goto switchD_001117b4_caseD_54;
    case 'U':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'U';
        goto LAB_001122f1;
      }
      break;
    case 'W':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'W';
        goto LAB_00112246;
      }
      break;
    case 'X':
    case 'c':
    case 'x':
      local_4c8._0_1_ = cVar11;
      cVar5 = '\0';
      if (local_4b0 != 0x4f) goto LAB_001118e8;
      break;
    case 'Y':
      if (local_4b0 == 0x45) goto LAB_00112d3e;
      if (local_4b0 != 0x4f) goto switchD_00111734_caseD_59;
      goto LAB_00112631;
    case 'Z':
      goto switchD_001117b4_caseD_5a;
    case 'a':
      if (local_4b0 == 0) goto switchD_00111734_caseD_61;
      break;
    case 'b':
    case 'h':
      local_4c8._0_1_ = cVar11;
      if (cVar5 != '\0') goto LAB_0011270b;
LAB_00112711:
      if (local_4b0 == 0) goto LAB_001125fa;
LAB_00112631:
      cVar11 = *param_3;
      break;
    case 'd':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'd';
        goto LAB_0011290d;
      }
      break;
    case 'e':
      if (local_4b0 != 0x45) {
        cVar25 = 'e';
        goto LAB_001128e2;
      }
      break;
    case 'j':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'j';
        goto LAB_00112898;
      }
      break;
    case 'k':
      if (local_4b0 != 0x45) {
        cVar25 = 'k';
        goto LAB_0011286d;
      }
      break;
    case 'l':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'l';
        goto LAB_001126d0;
      }
      break;
    case 'm':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'm';
        goto LAB_0011267c;
      }
      break;
    case 'n':
      goto switchD_001117b4_caseD_6e;
    case 'p':
      cVar25 = '\0';
      goto LAB_00111e8f;
    case 'q':
      local_4c8._0_1_ = 'q';
      goto LAB_001124d3;
    case 'r':
      goto switchD_001117b4_caseD_72;
    case 's':
      goto switchD_001117b4_caseD_73;
    case 't':
      goto switchD_001117b4_caseD_74;
    case 'u':
      bVar26 = local_4b0 == 0x4f;
      cVar5 = cVar25;
      local_4c8._0_1_ = 'u';
      goto LAB_001120a9;
    case 'w':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'w';
        goto LAB_00112523;
      }
      break;
    case 'y':
      if (local_4b0 != 0x45) {
        local_4c8._0_1_ = 'y';
        goto LAB_001121f7;
      }
LAB_00112d3e:
      local_4b0 = 0;
      local_4c8._0_1_ = cVar11;
      cVar5 = 'E';
      goto LAB_0011210e;
    case 'z':
      local_4c8._0_1_ = 'z';
      goto LAB_00112922;
    }
    goto LAB_001117e2;
  }
  cVar11 = (char)local_4c8;
  switch(uVar7 & 0xff) {
  case 0:
    local_4c8._0_1_ = param_3[-1];
switchD_001117b4_caseD_0:
    param_3 = param_3 + -1;
    cVar11 = (char)local_4c8;
  default:
LAB_001117e2:
    if (cVar11 == '%') {
LAB_00111a10:
      __n = 1;
      __dest = param_3;
    }
    else {
      iVar15 = 1;
      __dest = param_3;
      do {
        __dest = __dest + -1;
        iVar15 = iVar15 + 1;
      } while (*__dest != '%');
      __n = SEXT48(iVar15);
    }
    uVar13 = 0;
    if (-1 < (int)uVar16) {
      uVar13 = uVar16;
    }
    uVar7 = SEXT48((int)uVar13);
    local_4c8 = __n;
    if (__n <= uVar7) {
      local_4c8 = uVar7;
    }
    if ((ulong)(param_2 - (long)pcVar24) <= local_4c8) goto LAB_00111760;
    if (param_1 != (char *)0x0) {
      if (__n < uVar7) {
        __n_00 = (long)(int)uVar16 - __n;
        if (local_4c0 == 0x30) {
          __dest_00 = param_1 + __n_00;
          memset(param_1,0x30,__n_00);
        }
        else {
          __dest_00 = param_1 + __n_00;
          memset(param_1,0x20,__n_00);
        }
      }
      goto LAB_00111846;
    }
    goto LAB_00111858;
  case 0x25:
switchD_00111734_caseD_25:
    uVar13 = 0;
    if (-1 < (int)uVar16) {
      uVar13 = uVar16;
    }
    __n = SEXT48((int)uVar13);
    if (__n == 0) {
      __n = 1;
    }
    if ((ulong)(param_2 - (long)pcVar24) <= __n) goto LAB_00111760;
    if (param_1 != (char *)0x0) {
      __dest = param_1;
      if (1 < (int)uVar13) {
        __n_00 = (long)(int)uVar16 - 1;
        if (local_4c0 == 0x30) {
          __dest = param_1 + __n_00;
          memset(param_1,0x30,__n_00);
        }
        else {
          __dest = param_1 + __n_00;
          memset(param_1,0x20,__n_00);
        }
      }
      param_1 = __dest + 1;
      *__dest = *param_3;
    }
    pcVar24 = pcVar24 + __n;
    goto LAB_0011162d;
  case 0x3a:
    local_4b0 = 0;
    local_4c8._0_1_ = cVar25;
LAB_0011213f:
    cVar5 = param_3[1];
    __n_02 = param_3 + 1;
    lVar20 = 1;
    if (cVar5 == ':') {
      lVar20 = 1;
      __dest = param_3 + 2;
      do {
        __n_02 = __dest;
        cVar5 = *__n_02;
        lVar20 = lVar20 + 1;
        __dest = __n_02 + 1;
      } while (cVar5 == ':');
    }
    if (cVar5 != 'z') {
      cVar11 = *param_3;
      goto LAB_001117e2;
    }
    param_3 = __n_02;
    if (-1 < param_4->tm_isdst) {
      iVar15 = (int)param_4->tm_gmtoff;
      bVar4 = (byte)((ulong)param_4->tm_gmtoff >> 0x18);
      uVar13 = iVar15 / 0xe10;
      uVar12 = (iVar15 / 0x3c) % 0x3c;
      cVar5 = (char)local_4b0;
      if (lVar20 == 1) {
LAB_00112e82:
        bVar21 = (bool)(bVar4 >> 7);
        bVar3 = true;
        uVar13 = uVar13 * 100 + uVar12;
        bVar26 = local_4b0 == 0x4f;
        uVar12 = 4;
        local_4b0 = 6;
      }
      else {
        if (lVar20 == 0) goto LAB_0011297f;
        if (lVar20 != 2) {
          if (lVar20 != 3) goto LAB_00112631;
          if (iVar15 % 0x3c == 0) {
            if (uVar12 == 0) {
              bVar21 = (bool)(bVar4 >> 7);
              bVar26 = local_4b0 == 0x4f;
              bVar3 = true;
              local_4b0 = 3;
              goto LAB_001120f7;
            }
            goto LAB_00112e82;
          }
        }
        iVar18 = uVar12 * 100;
        bVar21 = (bool)(bVar4 >> 7);
        bVar3 = true;
        uVar12 = 0x14;
        uVar13 = uVar13 * 10000 + iVar18 + iVar15 % 0x3c;
        bVar26 = local_4b0 == 0x4f;
        local_4b0 = 9;
      }
      goto LAB_001120f7;
    }
    goto LAB_0011162d;
  case 0x41:
switchD_00111734_caseD_41:
    local_4c8._0_1_ = 'A';
    if (cVar5 != '\0') {
      cVar22 = cVar5;
    }
    goto LAB_001125fa;
  case 0x42:
switchD_00111734_caseD_42:
    local_4c8._0_1_ = 'B';
    if (cVar5 != '\0') {
      cVar22 = cVar5;
    }
    goto LAB_001125fa;
  case 0x43:
    local_4b0 = 0;
    local_4c8._0_1_ = cVar25;
LAB_001127c3:
    cVar5 = (char)local_4b0;
    bVar3 = false;
    iVar18 = param_4->tm_year;
    iVar15 = iVar18 / 100 + 0x13;
    bVar21 = iVar18 < -0x76c;
    uVar13 = iVar15 - ((uint)(0 < iVar15) & (uint)(iVar18 % 100) >> 0x1f);
    bVar26 = local_4b0 == 0x4f;
    local_4b0 = 2;
    uVar12 = 0;
    __n_02 = param_3;
    goto LAB_001120f7;
  case 0x44:
LAB_001127a5:
    __dest = "%m/%d/%y";
    goto LAB_00111d99;
  case 0x46:
LAB_001124c2:
    __dest = "%Y-%m-%d";
    goto LAB_00111d99;
  case 0x47:
  case 0x56:
  case 0x67:
    uVar12 = 0;
    local_4c8._0_1_ = cVar25;
LAB_0011235d:
    cVar5 = (char)uVar12;
    iVar18 = param_4->tm_year;
    uVar13 = ((iVar18 >> 0x1f & 400U) - 100) + iVar18;
    iVar17 = param_4->tm_wday;
    iVar1 = param_4->tm_yday;
    iVar15 = (iVar1 - iVar17) + 0x17e;
    iVar15 = (iVar1 - iVar15) + 3 + (iVar15 / 7) * 7;
    if (iVar15 < 0) {
      uVar13 = uVar13 - 1;
      iVar15 = 0x16d;
      if (((uVar13 & 3) == 0) && (iVar15 = 0x16e, uVar13 == ((int)uVar13 / 100) * 100)) {
        iVar15 = (uint)(uVar13 == ((int)uVar13 / 400) * 400) + 0x16d;
      }
      iVar23 = -1;
      iVar17 = ((iVar1 + iVar15) - iVar17) + 0x17e;
      iVar17 = ((iVar1 + iVar15) - iVar17) + 3 + (iVar17 / 7) * 7;
    }
    else {
      iVar6 = 0x16d;
      if (((uVar13 & 3) == 0) && (iVar6 = 0x16e, uVar13 == ((int)uVar13 / 100) * 100)) {
        iVar6 = (uint)(uVar13 == ((int)uVar13 / 400) * 400) + 0x16d;
      }
      iVar23 = 1;
      iVar17 = ((iVar1 - iVar6) - iVar17) + 0x17e;
      iVar17 = ((iVar1 - iVar6) - iVar17) + 3 + (iVar17 / 7) * 7;
      if (iVar17 < 0) {
        iVar23 = 0;
        iVar17 = iVar15;
      }
    }
    if (cVar11 != 'G') {
      if (cVar11 == 'g') {
        uVar13 = (iVar18 % 100 + iVar23) % 100;
        if ((int)uVar13 < 0) {
          if (-0x76c - iVar23 <= iVar18) goto LAB_00112a69;
          goto LAB_001124b8;
        }
      }
      else {
        uVar13 = iVar17 / 7 + 1;
      }
      break;
    }
    uVar13 = iVar23 + 0x76c + iVar18;
    bVar3 = false;
    local_4b0 = 4;
    bVar21 = iVar18 < -0x76c - iVar23;
    bVar26 = uVar12 == 0x4f;
    uVar12 = 0;
    __n_02 = param_3;
    goto LAB_001120f7;
  case 0x48:
    uVar12 = 0;
    local_4c8._0_1_ = cVar25;
LAB_0011234d:
    uVar13 = param_4->tm_hour;
    break;
  case 0x49:
    local_4b0 = 0;
    local_4c8._0_1_ = cVar25;
LAB_0011232b:
    cVar5 = (char)local_4b0;
    bVar26 = local_4b0 == 0x4f;
    local_4b0 = 2;
    goto LAB_001120e8;
  case 0x4d:
    uVar12 = 0;
    local_4c8._0_1_ = cVar25;
LAB_0011231b:
    uVar13 = param_4->tm_min;
    break;
  case 0x4e:
    local_4b0 = 0;
    local_4c8._0_1_ = cVar25;
LAB_0011229b:
    cVar5 = (char)local_4b0;
    uVar13 = param_8;
    if (uVar16 == 0xffffffff) {
      bVar26 = local_4b0 == 0x4f;
      uVar16 = 9;
      local_4b0 = 9;
    }
    else {
      uVar12 = uVar16;
      if ((int)uVar16 < 9) {
        do {
          uVar12 = uVar12 + 1;
          uVar13 = (int)uVar13 / 10;
        } while (uVar12 != 9);
      }
      bVar26 = local_4b0 == 0x4f;
      local_4b0 = uVar16;
    }
    goto LAB_001120e8;
  case 0x50:
    local_4b0 = 0;
switchD_001117b4_caseD_50:
    cVar25 = '\x01';
LAB_00111e8f:
    if (cVar5 == '\0') {
      local_4c8._0_1_ = 'p';
      cVar5 = cVar25;
    }
    else {
      local_4c8._0_1_ = 'p';
      cVar22 = '\0';
    }
    goto LAB_001118e8;
  case 0x52:
switchD_001117b4_caseD_52:
    __dest = "%H:%M";
    goto LAB_00111d99;
  case 0x53:
    uVar12 = 0;
    local_4c8._0_1_ = cVar25;
LAB_0011228f:
    uVar13 = param_4->tm_sec;
    break;
  case 0x54:
switchD_001117b4_caseD_54:
    __dest = "%H:%M:%S";
LAB_00111d99:
    uVar7 = FUN_00111540(0,0xffffffffffffffff,__dest,param_4,__n,param_6,param_7,(ulong)param_8);
    uVar13 = 0;
    if (-1 < (int)uVar16) {
      uVar13 = uVar16;
    }
    uVar9 = SEXT48((int)uVar13);
    uVar19 = uVar9;
    if (uVar9 <= uVar7) {
      uVar19 = uVar7;
    }
    if ((ulong)(param_2 - (long)pcVar24) <= uVar19) goto LAB_00111760;
    if (param_1 != (char *)0x0) {
      if (uVar7 < uVar9) {
        __n_00 = (long)(int)uVar16 - uVar7;
        if (local_4c0 == 0x30) {
          __dest_00 = param_1 + __n_00;
          memset(param_1,0x30,__n_00);
        }
        else {
          __dest_00 = param_1 + __n_00;
          memset(param_1,0x20,__n_00);
        }
      }
      param_1 = __dest_00 + uVar7;
      FUN_00111540(__dest_00,param_2 - (long)pcVar24,__dest,param_4,__n,param_6,param_7,
                   (ulong)param_8);
    }
    pcVar24 = pcVar24 + uVar19;
    goto LAB_0011162d;
  case 0x55:
    uVar12 = 0;
    local_4c8._0_1_ = cVar25;
LAB_001122f1:
    uVar13 = ((param_4->tm_yday - param_4->tm_wday) + 7) / 7;
    break;
  case 0x57:
    uVar12 = 0;
    local_4c8._0_1_ = cVar25;
LAB_00112246:
    iVar15 = param_4->tm_wday + 6;
    uVar13 = (((iVar15 / 7) * 7 - iVar15) + 7 + param_4->tm_yday) / 7;
    break;
  case 0x58:
  case 99:
  case 0x78:
    local_4b0 = 0;
switchD_001117b4_caseD_72:
    local_4c8._0_1_ = cVar11;
    cVar5 = '\0';
LAB_001118e8:
    if (local_4b0 == 0) goto LAB_00111906;
    local_456 = (char)local_4b0;
    local_4b0 = 0;
    goto LAB_00112121;
  case 0x59:
switchD_00111734_caseD_59:
    bVar3 = false;
    local_4b0 = 4;
    bVar21 = param_4->tm_year < -0x76c;
    uVar13 = param_4->tm_year + 0x76c;
    uVar12 = 0;
    __n_02 = param_3;
    goto LAB_00111ee0;
  case 0x5a:
switchD_001117b4_caseD_5a:
    if (cVar5 != '\0') {
      cVar22 = '\0';
    }
    __n_00 = strlen(__s);
    uVar13 = 0;
    if (-1 < (int)uVar16) {
      uVar13 = uVar16;
    }
    uVar7 = SEXT48((int)uVar13);
    __n = uVar7;
    if (uVar7 <= __n_00) {
      __n = __n_00;
    }
    if ((ulong)(param_2 - (long)pcVar24) <= __n) goto LAB_00111760;
    if (param_1 != (char *)0x0) {
      __dest = param_1;
      if (__n_00 < uVar7) {
        __n_01 = (long)(int)uVar16 - __n_00;
        if (local_4c0 == 0x30) {
          memset(param_1,0x30,__n_01);
          __dest = param_1 + __n_01;
        }
        else {
          __dest = param_1 + __n_01;
          memset(param_1,0x20,__n_01);
        }
      }
      if (cVar5 == '\0') {
        if (cVar22 == '\0') {
          memcpy(__dest,__s,__n_00);
        }
        else {
          FUN_001114f0();
        }
      }
      else {
        FUN_001114a0();
      }
      param_1 = __dest + __n_00;
    }
    pcVar24 = pcVar24 + __n;
    goto LAB_0011162d;
  case 0x61:
switchD_00111734_caseD_61:
    local_4c8._0_1_ = 'a';
    if (cVar5 != '\0') {
      cVar22 = cVar5;
    }
    goto LAB_001125fa;
  case 0x62:
  case 0x68:
    local_4c8._0_1_ = cVar25;
    if (cVar5 != '\0') {
      local_4b0 = 0;
LAB_0011270b:
      cVar22 = '\x01';
      goto LAB_00112711;
    }
LAB_001125fa:
    cVar5 = '\0';
    local_4b0 = 0;
    goto LAB_00111906;
  case 100:
    uVar12 = 0;
    local_4c8._0_1_ = cVar25;
LAB_0011290d:
    uVar13 = param_4->tm_mday;
    break;
  case 0x65:
    local_4b0 = 0;
LAB_001128e2:
    uVar13 = param_4->tm_mday;
    local_4c8._0_1_ = cVar25;
    goto LAB_001126d0;
  case 0x6a:
    uVar12 = 0;
    local_4c8._0_1_ = cVar25;
LAB_00112898:
    cVar5 = (char)uVar12;
    bVar3 = false;
    local_4b0 = 3;
    bVar21 = param_4->tm_yday < -1;
    uVar13 = param_4->tm_yday + 1;
    bVar26 = uVar12 == 0x4f;
    uVar12 = 0;
    __n_02 = param_3;
    goto LAB_001120f7;
  case 0x6b:
    local_4b0 = 0;
LAB_0011286d:
    uVar13 = param_4->tm_hour;
    local_4c8._0_1_ = cVar25;
    goto LAB_001126d0;
  case 0x6c:
    local_4b0 = 0;
    local_4c8._0_1_ = cVar25;
LAB_001126d0:
    cVar5 = (char)local_4b0;
    bVar26 = local_4b0 == 0x4f;
    local_4b0 = 2;
    if ((local_4c0 != 0x30) && (local_4c0 != 0x2d)) {
      local_4c0 = 0x5f;
    }
    goto LAB_001120e8;
  case 0x6d:
    uVar12 = 0;
    local_4c8._0_1_ = cVar25;
LAB_0011267c:
    cVar5 = (char)uVar12;
    bVar3 = false;
    local_4b0 = 2;
    bVar21 = param_4->tm_mon < -1;
    uVar13 = param_4->tm_mon + 1;
    bVar26 = uVar12 == 0x4f;
    uVar12 = 0;
    __n_02 = param_3;
    goto LAB_001120f7;
  case 0x6e:
switchD_001117b4_caseD_6e:
    uVar13 = 0;
    if (-1 < (int)uVar16) {
      uVar13 = uVar16;
    }
    __n = SEXT48((int)uVar13);
    if (__n == 0) {
      __n = 1;
    }
    if ((ulong)(param_2 - (long)pcVar24) <= __n) goto LAB_00111760;
    if (param_1 != (char *)0x0) {
      __dest = param_1;
      if (1 < (int)uVar13) {
        __n_00 = (long)(int)uVar16 - 1;
        if (local_4c0 == 0x30) {
          __dest = param_1 + __n_00;
          memset(param_1,0x30,__n_00);
        }
        else {
          __dest = param_1 + __n_00;
          memset(param_1,0x20,__n_00);
        }
      }
      *__dest = '\n';
      param_1 = __dest + 1;
    }
    goto LAB_00111aa0;
  case 0x70:
    if (cVar5 == '\0') {
      local_4b0 = 0;
    }
    else {
      cVar22 = '\0';
      local_4b0 = 0;
    }
    goto LAB_00111906;
  case 0x71:
    local_4b0 = 0;
    local_4c8._0_1_ = cVar25;
LAB_001124d3:
    if (local_4b0 == 0x4f) {
      local_4b0 = 1;
      __n_02 = param_3;
      cVar5 = 'O';
      goto LAB_0011210e;
    }
    bVar3 = false;
    bVar21 = false;
    local_4b0 = 1;
    uVar12 = 0;
    uVar13 = (param_4->tm_mon * 0xb >> 5) + 1;
    goto LAB_00111ee7;
  case 0x72:
    cVar5 = '\0';
    local_4b0 = 0;
    goto LAB_00111906;
  case 0x73:
switchD_001117b4_caseD_73:
    local_498 = *(undefined8 *)param_4;
    local_490 = *(undefined8 *)&param_4->tm_hour;
    local_488 = *(undefined8 *)&param_4->tm_mon;
    local_480 = *(undefined8 *)&param_4->tm_wday;
    local_478 = *(undefined8 *)&param_4->tm_isdst;
    local_470 = param_4->tm_gmtoff;
    local_468 = param_4->tm_zone;
    lVar8 = FUN_00114cd0(param_7,&local_498);
    __dest = acStack1073;
    lVar20 = lVar8;
    do {
      __dest = __dest + -1;
      lVar2 = lVar20 / 10;
      cVar5 = (char)lVar20 + (char)lVar2 * -10;
      if (lVar8 < 0) {
        cVar5 = -cVar5;
      }
      *__dest = cVar5 + '0';
      lVar20 = lVar2;
    } while (lVar2 != 0);
    cVar5 = '-';
    local_4b0 = 1;
    if (0 < (int)uVar16) {
      local_4b0 = uVar16;
    }
    if (lVar8 < 0) goto LAB_00111f5a;
    goto LAB_00111c0d;
  case 0x74:
switchD_001117b4_caseD_74:
    uVar13 = 0;
    if (-1 < (int)uVar16) {
      uVar13 = uVar16;
    }
    __n = SEXT48((int)uVar13);
    if (__n == 0) {
      __n = 1;
    }
    if ((ulong)(param_2 - (long)pcVar24) <= __n) goto LAB_00111760;
    if (param_1 != (char *)0x0) {
      __dest = param_1;
      if (1 < (int)uVar13) {
        __n_00 = (long)(int)uVar16 - 1;
        if (local_4c0 == 0x30) {
          __dest = param_1 + __n_00;
          memset(param_1,0x30,__n_00);
        }
        else {
          __dest = param_1 + __n_00;
          memset(param_1,0x20,__n_00);
        }
      }
      *__dest = '\t';
      param_1 = __dest + 1;
    }
LAB_00111aa0:
    pcVar24 = pcVar24 + __n;
    goto LAB_0011162d;
  case 0x75:
    bVar26 = false;
    cVar5 = '\0';
    local_4c8._0_1_ = cVar25;
LAB_001120a9:
    local_4b0 = 1;
    uVar13 = (param_4->tm_wday + 6) % 7 + 1;
    goto LAB_001120e8;
  case 0x77:
    local_4b0 = 0;
    local_4c8._0_1_ = cVar25;
LAB_00112523:
    cVar5 = (char)local_4b0;
    bVar26 = local_4b0 == 0x4f;
    local_4b0 = 1;
    uVar13 = param_4->tm_wday;
    goto LAB_001120e8;
  case 0x79:
    uVar12 = 0;
    local_4c8._0_1_ = cVar25;
LAB_001121f7:
    uVar13 = param_4->tm_year % 100;
    if ((int)uVar13 < 0) {
      if (param_4->tm_year < -0x76c) {
LAB_001124b8:
        uVar13 = -uVar13;
      }
      else {
LAB_00112a69:
        uVar13 = uVar13 + 100;
      }
    }
    break;
  case 0x7a:
    local_4b0 = 0;
    local_4c8._0_1_ = cVar25;
LAB_00112922:
    if (-1 < param_4->tm_isdst) {
      iVar15 = (int)param_4->tm_gmtoff;
      bVar4 = (byte)((ulong)param_4->tm_gmtoff >> 0x18);
      uVar13 = iVar15 / 0xe10;
      uVar12 = (iVar15 / 0x3c) % 0x3c;
      __n_02 = param_3;
LAB_0011297f:
      cVar5 = (char)local_4b0;
      bVar3 = true;
      uVar13 = uVar13 * 100 + uVar12;
      bVar26 = local_4b0 == 0x4f;
      bVar21 = (bool)(bVar4 >> 7);
      local_4b0 = 5;
      uVar12 = 0;
      goto LAB_001120f7;
    }
    goto LAB_0011162d;
  }
  cVar5 = (char)uVar12;
  bVar26 = uVar12 == 0x4f;
  local_4b0 = 2;
LAB_001120e8:
  uVar12 = 0;
  bVar3 = false;
  bVar21 = SUB41(uVar13 >> 0x1f,0);
  __n_02 = param_3;
LAB_001120f7:
  if (bVar21 == false) {
    if (!bVar26) {
LAB_00111ee0:
      param_3 = __n_02;
      if (bVar21 != false) goto LAB_00111ee5;
      goto LAB_00111ee7;
    }
LAB_0011210e:
    local_456 = cVar5;
    cVar5 = '\0';
    param_3 = __n_02;
LAB_00112121:
    __dest = acStack1109;
LAB_00111906:
    local_457 = 0x25;
    local_458 = ' ';
    *__dest = (char)local_4c8;
    __dest[1] = '\0';
    __n_00 = strftime(&local_448,0x400,&local_458,param_4);
    if (__n_00 != 0) {
      __n = __n_00 - 1;
      uVar13 = 0;
      if (-1 < (int)uVar16) {
        uVar13 = uVar16;
      }
      uVar7 = SEXT48((int)uVar13);
      local_4c8 = uVar7;
      if (uVar7 <= __n) {
        local_4c8 = __n;
      }
      if (local_4c8 < (ulong)(param_2 - (long)pcVar24)) {
        if (param_1 != (char *)0x0) {
          if ((local_4b0 == 0) && (__n < uVar7)) {
            __n_00 = (long)(int)uVar16 - __n;
            if (local_4c0 == 0x30) {
              memset(param_1,0x30,__n_00);
              __dest_00 = param_1 + __n_00;
            }
            else {
              __dest_00 = param_1 + __n_00;
              memset(param_1,0x20,__n_00);
            }
          }
          __dest = local_447;
          if (cVar5 == '\0') {
LAB_00111846:
            if (cVar22 == '\0') {
              memcpy(__dest_00,__dest,__n);
            }
            else {
              FUN_001114f0();
            }
          }
          else {
            FUN_001114a0();
          }
          param_1 = __dest_00 + __n;
        }
LAB_00111858:
        cVar5 = param_3[1];
        pcVar24 = pcVar24 + local_4c8;
        goto joined_r0x00111868;
      }
      goto LAB_00111760;
    }
  }
  else {
LAB_00111ee5:
    uVar13 = -uVar13;
    param_3 = __n_02;
LAB_00111ee7:
    __dest = acStack1073;
    do {
      __dest_00 = __dest;
      if ((uVar12 & 1) != 0) {
        __dest_00 = __dest + -1;
        __dest[-1] = ':';
      }
      uVar12 = (int)uVar12 >> 1;
      __dest = __dest_00 + -1;
      uVar14 = uVar13 / 10;
      __dest_00[-1] = (char)uVar13 + (char)uVar14 * -10 + '0';
      uVar13 = uVar14;
    } while ((uVar14 != 0) || (uVar12 != 0));
    if ((int)local_4b0 < (int)uVar16) {
      local_4b0 = uVar16;
    }
    if (bVar21 == false) {
      cVar5 = '+';
      if (bVar3) goto LAB_00111f5a;
LAB_00111c0d:
      __n_02 = acStack1073 + -(long)__dest;
      if (local_4c0 == 0x2d) {
LAB_00111c23:
        uVar13 = 0;
        if (-1 < (int)uVar16) {
          uVar13 = uVar16;
        }
        __dest_00 = (char *)(long)(int)uVar13;
      }
      else {
        cVar5 = '\0';
        bVar26 = false;
        iVar15 = local_4b0 - (int)__n_02;
        if (iVar15 < 1) goto LAB_00111c23;
LAB_00111f84:
        if (local_4c0 == 0x5f) {
          __n = SEXT48(iVar15);
          if ((ulong)(param_2 - (long)pcVar24) <= __n) goto LAB_00111760;
          if (param_1 != (char *)0x0) {
            memset(param_1,0x20,__n);
            local_4c0 = 0x5f;
            param_1 = param_1 + __n;
          }
          pcVar24 = pcVar24 + __n;
          if (iVar15 < (int)uVar16) {
            uVar16 = uVar16 - iVar15;
            uVar13 = 0;
            if (-1 < (int)uVar16) {
              uVar13 = uVar16;
            }
            __dest_00 = (char *)(long)(int)uVar13;
          }
          else {
            __dest_00 = (char *)0x0;
            uVar16 = 0;
          }
          if (bVar26) goto LAB_00112b17;
          goto LAB_00112ba4;
        }
        if ((ulong)(param_2 - (long)pcVar24) <= (ulong)(long)(int)local_4b0) goto LAB_00111760;
        if (bVar26) {
          uVar13 = 0;
          if (-1 < (int)uVar16) {
            uVar13 = uVar16;
          }
          uVar7 = SEXT48((int)uVar13);
          __n = 1;
          if (uVar7 != 0) {
            __n = uVar7;
          }
          if ((ulong)(param_2 - (long)pcVar24) <= __n) goto LAB_00111760;
          if (param_1 != (char *)0x0) {
            __dest_00 = param_1;
            if ((local_4b0 == 0) && (1 < uVar7)) {
              __n_00 = (long)(int)uVar16 - 1;
              local_4b8 = 0;
              local_4b0 = local_4b8;
              if (local_4c0 == 0x30) {
                __dest_00 = param_1 + __n_00;
                memset(param_1,0x30,__n_00);
              }
              else {
                __dest_00 = param_1 + __n_00;
                memset(param_1,0x20,__n_00);
              }
            }
            *__dest_00 = cVar5;
            pcVar24 = pcVar24 + __n;
            param_1 = __dest_00 + 1;
            goto LAB_00112043;
          }
          pcVar24 = pcVar24 + __n;
        }
        else {
LAB_00112043:
          if (param_1 != (char *)0x0) {
            memset(param_1,0x30,(long)iVar15);
            param_1 = param_1 + (long)iVar15;
          }
        }
        pcVar24 = pcVar24 + iVar15;
        __dest_00 = (char *)0x0;
        uVar16 = 0;
        __n_02 = acStack1073 + -(long)__dest;
      }
    }
    else {
      cVar5 = '-';
LAB_00111f5a:
      if (local_4c0 == 0x2d) {
        uVar13 = 0;
        if (-1 < (int)uVar16) {
          uVar13 = uVar16;
        }
        __dest_00 = (char *)(long)(int)uVar13;
LAB_00112b17:
        __n_02 = (char *)0x1;
        if (__dest_00 != (char *)0x0) {
          __n_02 = __dest_00;
        }
        if ((char *)(param_2 - (long)pcVar24) <= __n_02) goto LAB_00111760;
        if (param_1 != (char *)0x0) {
          if ((local_4b0 == 0) && ((char *)0x1 < __dest_00)) {
            memset(param_1,0x20,(long)(int)uVar16 - 1U);
            param_1 = param_1 + ((long)(int)uVar16 - 1U);
          }
          *param_1 = cVar5;
          param_1 = param_1 + 1;
        }
        pcVar24 = __n_02 + (long)pcVar24;
LAB_00112ba4:
        __n_02 = acStack1073 + -(long)__dest;
      }
      else {
        __n_02 = acStack1073 + -(long)__dest;
        iVar15 = (local_4b0 - 1) - (int)__n_02;
        if (0 < iVar15) {
          bVar26 = true;
          goto LAB_00111f84;
        }
        uVar13 = 0;
        if (-1 < (int)uVar16) {
          uVar13 = uVar16;
        }
        __dest_00 = (char *)(long)(int)uVar13;
        pcVar10 = (char *)0x1;
        if (__dest_00 != (char *)0x0) {
          pcVar10 = __dest_00;
        }
        if ((char *)(param_2 - (long)pcVar24) <= pcVar10) goto LAB_00111760;
        if (param_1 != (char *)0x0) {
          if ((local_4b0 == 0) && ((char *)0x1 < __dest_00)) {
            __n_00 = (long)(int)uVar16 - 1;
            local_4b0 = 0;
            if (local_4c0 == 0x30) {
              memset(param_1,0x30,__n_00);
              param_1 = param_1 + __n_00;
            }
            else {
              memset(param_1,0x20,__n_00);
              param_1 = param_1 + __n_00;
            }
          }
          *param_1 = cVar5;
          param_1 = param_1 + 1;
        }
        pcVar24 = pcVar10 + (long)pcVar24;
      }
    }
    pcVar10 = __dest_00;
    if (__dest_00 <= __n_02) {
      pcVar10 = __n_02;
    }
    if ((char *)(param_2 - (long)pcVar24) <= pcVar10) {
LAB_00111760:
      pcVar24 = (char *)0x0;
      goto LAB_00111763;
    }
    if (param_1 != (char *)0x0) {
      __dest_01 = param_1;
      if ((local_4b0 == 0) && (__n_02 < __dest_00)) {
        __n_00 = (long)(int)uVar16 - (long)__n_02;
        if (local_4c0 == 0x30) {
          __dest_01 = param_1 + __n_00;
          memset(param_1,0x30,__n_00);
        }
        else {
          __dest_01 = param_1 + __n_00;
          memset(param_1,0x20,__n_00);
        }
      }
      if (cVar22 == '\0') {
        memcpy(__dest_01,__dest,(size_t)__n_02);
      }
      else {
        FUN_001114f0();
      }
      param_1 = __dest_01 + (long)__n_02;
    }
    pcVar24 = pcVar10 + (long)pcVar24;
  }
LAB_0011162d:
  cVar5 = param_3[1];
joined_r0x00111868:
  param_3 = param_3 + 1;
  if (cVar5 == '\0') goto LAB_00111874;
  goto LAB_00111640;
}



``` 


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
>

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