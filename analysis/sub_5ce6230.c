unsigned __int64 __fastcall sub_5CE6230(__int64 a1, __int64 a2, __int64 a3, __int64 a4, __int64 a5)
{
  __int64 v5; // r11
  unsigned __int64 result; // rax
  int i; // r9d
  unsigned __int64 *v8; // rax
  __int64 v9; // rcx
  __int64 v10; // [rsp+0h] [rbp-A0h] BYREF
  _QWORD *v11; // [rsp+8h] [rbp-98h]
  _QWORD *v12; // [rsp+10h] [rbp-90h]
  _QWORD *v13; // [rsp+18h] [rbp-88h]
  __int64 v14; // [rsp+20h] [rbp-80h]
  __int64 v15; // [rsp+28h] [rbp-78h]
  unsigned __int64 *v16; // [rsp+30h] [rbp-70h]
  unsigned __int64 *v17; // [rsp+38h] [rbp-68h]
  unsigned __int64 *v18; // [rsp+40h] [rbp-60h]
  unsigned __int64 *v19; // [rsp+48h] [rbp-58h]
  unsigned __int64 *v20; // [rsp+50h] [rbp-50h]
  __int64 *v21; // [rsp+58h] [rbp-48h]
  bool v22; // [rsp+65h] [rbp-3Bh]
  bool v23; // [rsp+66h] [rbp-3Ah]
  bool v24; // [rsp+67h] [rbp-39h]
  _QWORD v25[7]; // [rsp+68h] [rbp-38h] BYREF

  result = __readfsqword(0x28u);
  v25[1] = result;
  for ( i = -1079672910; ; i = 355329591 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( i > 411975767 )
          {
            if ( i <= 1471315531 )
            {
              if ( i > 813642876 )
              {
                if ( i > 1062390292 )
                {
                  if ( i != 1062390293 )
                  {
                    v8 = v18;
                    goto LABEL_58;
                  }
                  v5 = v14 >> 2;
                  i = 831509242;
                }
                else if ( i == 813642877 )
                {
LABEL_63:
                  v17 = v25;
                  i = 1471315532;
                  if ( *(_QWORD *)v25[0] == *(_QWORD *)*v21 )
                    i = 1651543371;
                }
                else
                {
                  v15 = v5;
                  i = 2012198253;
                  if ( v5 > 0 )
                    i = 2107605420;
                }
              }
              else if ( i > 714338821 )
              {
                v12 = (_QWORD *)*v20;
                i = 1578746339;
              }
              else
              {
                if ( i == 411975768 )
                  goto LABEL_57;
                v24 = *v13 == *(_QWORD *)*v21;
                i = -90131025;
              }
            }
            else if ( i <= 2012198252 )
            {
              if ( i > 1651543370 )
              {
                if ( i == 1651543371 )
                {
                  v8 = v17;
LABEL_58:
                  result = *v8;
                  i = -462641868;
                }
                else
                {
                  a5 += 8;
                  v25[0] = a5;
                  i = -118024881;
                }
              }
              else if ( i == 1471315532 )
              {
                a5 += 8;
                v25[0] = a5;
                i = -2105298989;
              }
              else
              {
                i = 2050213043;
                if ( *v12 == *(_QWORD *)*v21 )
                  i = 411975768;
              }
            }
            else if ( i <= 2063670150 )
            {
              if ( i == 2012198253 )
              {
                v9 = (__int64)(*v19 - a5) >> 3;
                if ( v9 == 1 )
                  goto LABEL_66;
                if ( v9 == 2 )
                  goto LABEL_63;
                if ( v9 != 3 )
                {
LABEL_56:
                  v8 = v19;
                  goto LABEL_58;
                }
                v18 = v25;
                i = -1994438806;
              }
              else
              {
                a5 += 8;
                v25[0] = a5;
                v5 = v15 - 1;
                i = 831509242;
              }
            }
            else if ( i == 2063670151 )
            {
              v23 = *(_QWORD *)*v20 == *(_QWORD *)*v21;
              i = -781348762;
            }
            else
            {
              if ( i != 2107605420 )
              {
                v8 = v16;
                goto LABEL_58;
              }
              v20 = v25;
              v13 = (_QWORD *)v25[0];
              i = 703909952;
            }
          }
          if ( i > -462641869 )
            break;
          if ( i > -1287611807 )
          {
            if ( i > -995518044 )
            {
              if ( i == -995518043 )
              {
                i = -1667987963;
                if ( *v11 == *(_QWORD *)*v21 )
                  i = 1432514705;
              }
              else
              {
                i = 1798428483;
                if ( v23 )
                  i = -256876433;
              }
            }
            else
            {
              if ( i == -1287611806 )
                goto LABEL_57;
              v19 = (unsigned __int64 *)&v10;
              v21 = &v10 - 2;
              v25[0] = a1;
              v10 = a2;
              *(&v10 - 2) = a3;
              a5 = v25[0];
              v14 = (__int64)(*v19 - v25[0]) >> 3;
              i = 1062390293;
            }
          }
          else if ( i > -1667987964 )
          {
            a5 += 8;
            v25[0] = a5;
            if ( i == -1667987963 )
              i = 813642877;
            else
              i = 714338822;
          }
          else if ( i == -2105298989 )
          {
LABEL_66:
            v16 = v25;
            i = -436087817;
            if ( *(_QWORD *)v25[0] == *(_QWORD *)*v21 )
              i = 2130563704;
          }
          else
          {
            v11 = (_QWORD *)*v18;
            i = -995518043;
          }
        }
        if ( i <= -90131026 )
          break;
        if ( i > 207231441 )
        {
          if ( i != 207231442 )
            goto LABEL_56;
          goto LABEL_57;
        }
        if ( i == -90131025 )
        {
          i = 82365410;
          if ( v24 )
            i = -1287611806;
        }
        else
        {
          a5 += 8;
          v25[0] = a5;
          i = 2063670151;
        }
      }
      if ( i <= -143000603 )
        break;
      if ( i == -143000602 )
      {
        i = -1345956955;
        if ( v22 )
          i = 207231442;
      }
      else
      {
        v22 = *(_QWORD *)*v20 == *(_QWORD *)*v21;
        i = -143000602;
      }
    }
    if ( i != -436087817 )
      break;
    a5 += 8;
    v25[0] = a5;
  }
  if ( i == -256876433 )
  {
LABEL_57:
    v8 = v20;
    goto LABEL_58;
  }
  return result;
}
