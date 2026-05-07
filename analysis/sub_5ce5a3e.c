__int64 __fastcall sub_5CE5A3E(__int64 a1, __int64 a2)
{
  unsigned int v2; // ebp
  int v3; // r12d
  int v4; // eax
  void **v5; // rax
  char v7; // [rsp+5h] [rbp-B3h]
  bool v8; // [rsp+6h] [rbp-B2h]
  bool v9; // [rsp+7h] [rbp-B1h]
  unsigned int *v10; // [rsp+8h] [rbp-B0h]
  int v11; // [rsp+10h] [rbp-A8h]
  int v12; // [rsp+14h] [rbp-A4h]
  _WORD *v13; // [rsp+18h] [rbp-A0h]
  void **v14; // [rsp+20h] [rbp-98h]
  void **v15; // [rsp+28h] [rbp-90h]
  void **v16; // [rsp+30h] [rbp-88h]
  unsigned int n; // [rsp+3Ch] [rbp-7Ch]
  void *s; // [rsp+48h] [rbp-70h]
  void *v19; // [rsp+50h] [rbp-68h]
  void *v20; // [rsp+58h] [rbp-60h]
  unsigned int *v21; // [rsp+60h] [rbp-58h]
  void **v22; // [rsp+68h] [rbp-50h]
  void *v23; // [rsp+70h] [rbp-48h]
  unsigned int *v24; // [rsp+78h] [rbp-40h]
  void *ptr; // [rsp+80h] [rbp-38h]

  v7 = *(_BYTE *)(*(_QWORD *)(a1 + 24) + a2);
  v4 = 336131509;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            while ( v4 <= 164550134 )
            {
              if ( v4 > -530487570 )
              {
                if ( v4 > -216357702 )
                {
                  if ( v4 > 55666316 )
                  {
                    if ( v4 == 55666317 )
                    {
                      free(*v16);
                      *v16 = 0;
                      free(v10);
                      v4 = -210776222;
                    }
                    else
                    {
                      v14 = (void **)(v10 + 2);
                      s = (void *)*((_QWORD *)v10 + 1);
                      v4 = 807124281;
                      if ( !s )
                        v4 = -1808694390;
                    }
                  }
                  else if ( v4 == -216357701 )
                  {
                    v4 = -949632101;
                    if ( v11 == 20 )
                      v4 = 163224259;
                  }
                  else
                  {
LABEL_74:
                    v4 = 1066791890;
                  }
                }
                else if ( v4 > -359454207 )
                {
                  if ( v4 == -359454206 )
                  {
                    v15 = v22;
                    v19 = *v22;
                    v8 = *v22 != 0;
                    v4 = -1127796668;
                  }
                  else
                  {
                    v4 = -565261887;
                    if ( v12 == 51 )
                      v4 = 349966219;
                  }
                }
                else if ( v4 == -530487569 )
                {
                  memset(v23, 0, *v24);
                  ptr = *v15;
                  v4 = 164550135;
                }
                else
                {
                  v20 = *v16;
                  v9 = *v16 != 0;
                  v4 = 1738606352;
                }
              }
              else if ( v4 > -1061679319 )
              {
                if ( v4 > -793275657 )
                {
                  if ( v4 == -793275656 )
                  {
                    v23 = v19;
                    v24 = v10;
                    v4 = -530487569;
                  }
                  else
                  {
                    v4 = 1066791890;
                    if ( *v13 == 10 )
                      v4 = 1318007447;
                  }
                }
                else if ( v4 == -1061679318 )
                {
                  n = *v21;
                  v4 = 418970389;
                }
                else
                {
                  v4 = -1808694390;
                  if ( v11 == 50 )
                    v4 = 163224259;
                }
              }
              else if ( v4 > -1808694391 )
              {
                if ( v4 == -1808694390 )
                {
                  v12 = (unsigned __int16)*v13;
                  v4 = 1783727706;
                  if ( v12 == 31 )
                    v4 = 349966219;
                }
                else
                {
                  v4 = -565261887;
                  if ( v8 )
                    v4 = -793275656;
                }
              }
              else if ( v4 == -1982134814 )
              {
                memset(v20, 0, *v10);
                v4 = 55666317;
              }
              else
              {
                v4 = 1759565749;
                v2 = 0;
              }
            }
            if ( v4 > 1066791889 )
              break;
            if ( v4 > 667553887 )
            {
              if ( v4 > 925847268 )
              {
                if ( v4 == 925847269 )
                {
                  v4 = 1759565749;
                  if ( !v3 )
                    v4 = -1976545990;
                  LOBYTE(v2) = 1;
                }
                else
                {
                  *(_BYTE *)(*(_QWORD *)(a1 + 24) + a2) = 0;
                  v4 = 667553888;
                }
              }
              else if ( v4 == 667553888 )
              {
                v4 = 925847269;
                v3 = 1;
              }
              else
              {
                v21 = v10;
                v4 = -1061679318;
              }
            }
            else if ( v4 > 349966218 )
            {
              if ( v4 != 349966219 )
              {
                memset(s, 0, n);
                free(*v14);
                v5 = v14;
LABEL_73:
                *v5 = 0;
                free(v10);
                goto LABEL_74;
              }
              v22 = (void **)(v10 + 2);
              v4 = -359454206;
            }
            else
            {
              if ( v4 == 164550135 )
              {
                free(ptr);
                v5 = v15;
                goto LABEL_73;
              }
              v4 = 2096001071;
              if ( (v7 & 1) == 0 )
                v4 = -1976545990;
            }
          }
          if ( v4 > 1738606351 )
            break;
          if ( v4 > 1245597637 )
          {
            if ( v4 == 1245597638 )
            {
              v4 = 925847269;
              v3 = 0;
            }
            else
            {
              v16 = (void **)(v10 + 2);
              v4 = -430400741;
            }
          }
          else if ( v4 == 1066791890 )
          {
            *(_QWORD *)(*(_QWORD *)(a1 + 16) + 8 * a2) = 0;
            v4 = 978916273;
          }
          else
          {
            v13 = v10 + 1;
            v11 = *((unsigned __int16 *)v10 + 2);
            v4 = 2006709359;
            if ( v11 == 30 )
              v4 = 163224259;
          }
        }
        if ( v4 <= 2006709358 )
          break;
        if ( v4 == 2006709359 )
        {
          v4 = -216357701;
          if ( v11 == 32 )
            v4 = 163224259;
        }
        else
        {
          v10 = *(unsigned int **)(*(_QWORD *)(a1 + 16) + 8 * a2);
          v4 = 1182167982;
          if ( !v10 )
            v4 = 1245597638;
        }
      }
      if ( v4 != 1738606352 )
        break;
      v4 = 1066791890;
      if ( v9 )
        v4 = -1982134814;
    }
    if ( v4 != 1783727706 )
      break;
    v4 = -324945797;
    if ( v12 == 33 )
      v4 = 349966219;
  }
  LOBYTE(v2) = v2 & 1;
  return v2;
}
