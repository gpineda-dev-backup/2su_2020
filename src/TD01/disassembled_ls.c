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


