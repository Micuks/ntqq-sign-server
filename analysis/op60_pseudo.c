// ===== sign_fn @ 0x56d81d1 =====
__int64 __fastcall sub_56D81D1(__int64 a1, __int64 a2, unsigned int a3, int a4, _BYTE *a5)
{
  int v6; // r9d
  __int64 v7; // rbp
  void *v8; // rax
  bool v9; // zf
  int v10; // ecx
  char *v11; // rax
  int i; // eax
  char v13; // bp
  char *v14; // r15
  char v15; // bp
  char *v16; // r12
  char v17; // bp
  char v19; // [rsp+0h] [rbp-168h]
  char v20; // [rsp+2h] [rbp-166h]
  char v21; // [rsp+3h] [rbp-165h]
  int v22; // [rsp+4h] [rbp-164h]
  int v23; // [rsp+8h] [rbp-160h]
  char v24; // [rsp+Ch] [rbp-15Ch]
  char *haystack; // [rsp+18h] [rbp-150h]
  Dl_info info; // [rsp+68h] [rbp-100h] BYREF
  unsigned __int64 v28; // [rsp+88h] [rbp-E0h]
  char *v29; // [rsp+90h] [rbp-D8h] BYREF
  size_t v30; // [rsp+98h] [rbp-D0h]
  char v31; // [rsp+A0h] [rbp-C8h] BYREF
  char *v32; // [rsp+B0h] [rbp-B8h] BYREF
  size_t v33; // [rsp+B8h] [rbp-B0h]
  char v34; // [rsp+C0h] [rbp-A8h] BYREF
  char needle[8]; // [rsp+D0h] [rbp-98h] BYREF
  size_t v36; // [rsp+D8h] [rbp-90h] BYREF
  _BYTE v37[16]; // [rsp+E0h] [rbp-88h] BYREF
  void *v38[2]; // [rsp+F0h] [rbp-78h] BYREF
  _BYTE v39[16]; // [rsp+100h] [rbp-68h] BYREF
  void *v40[2]; // [rsp+110h] [rbp-58h] BYREF
  char v41; // [rsp+120h] [rbp-48h] BYREF
  unsigned __int64 v42; // [rsp+130h] [rbp-38h]
  const void *retaddr; // [rsp+168h] [rbp+0h]

  v22 = a4;
  v42 = __readfsqword(0x28u);
  v23 = dladdr(retaddr, &info);
  v7 = a2 + a3;
  LODWORD(v8) = 316580256;
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( (int)v8 > 293535785 )
        {
          if ( (int)v8 > 455986752 )
          {
            if ( (_DWORD)v8 == 455986753 )
            {
              needle[0] = 1;
              needle[1] = 47;
              needle[2] = 85;
              needle[3] = 83;
              needle[4] = 65;
              needle[5] = 87;
              needle[6] = 86;
              needle[7] = 64;
              LOWORD(v36) = 1366;
              qmemcpy((char *)&v36 + 2, "DFLJ", 4);
              v32 = v37;
              v10 = 224002709;
              v11 = (char *)&v36 + 6;
              while ( v10 != 1083977141 )
              {
                *v11++ = 0;
                v10 = 224002709;
                if ( v11 == v32 )
                  v10 = 1083977141;
              }
              v20 = needle[0];
              for ( i = 1794684978; ; i = -2094600744 )
              {
                while ( 1 )
                {
                  while ( i > -350935053 )
                  {
                    if ( i > 1794684977 )
                    {
                      if ( i == 1856409910 )
                      {
                        HIWORD(v36) = 0;
                        needle[0] = 0;
                        i = -1008665137;
                      }
                      else
                      {
                        i = -1276824369;
                        if ( (v20 & 1) == 0 )
                          i = -1008665137;
                      }
                    }
                    else if ( i == -350935052 )
                    {
                      v24 = v28;
                      v29 = &needle[2];
                      v21 = needle[v28 + 2];
                      i = -828581152;
                    }
                    else
                    {
                      i = 1856409910;
                      if ( v28 < 0xC )
                        i = -350935052;
                    }
                  }
                  if ( i > -1008665138 )
                    break;
                  if ( i == -2094600744 )
                    v28 = (unsigned __int64)v32;
                  else
                    v28 = 0;
                  i = 1353057516;
                }
                if ( i != -828581152 )
                  break;
                v29[v28] = needle[1] ^ v21 ^ (v24 + 1) ^ 0xC;
                v32 = (char *)(v28 + 1);
              }
              v9 = strstr(haystack, &needle[2]) == 0;
              LODWORD(v8) = -1270187572;
              if ( v9 )
                LODWORD(v8) = 293535786;
            }
            else if ( (_DWORD)v8 == 2121027539 )
            {
              haystack = (char *)info.dli_fname;
              v9 = info.dli_fname == 0;
              LODWORD(v8) = 455986753;
              goto LABEL_14;
            }
          }
          else if ( (_DWORD)v8 == 293535786 )
          {
            dword_7DB82C8 = 1;
            LODWORD(v8) = -2138602275;
          }
          else if ( (_DWORD)v8 == 316580256 )
          {
            v9 = v23 == 0;
            LODWORD(v8) = 2121027539;
LABEL_14:
            if ( v9 )
              LODWORD(v8) = -2138602275;
          }
        }
        if ( (int)v8 > -641595236 )
          break;
        if ( (_DWORD)v8 == -2138602275 )
        {
          __gnu_cxx::__to_xstring<std::string,char>(
            (unsigned int)v40,
            (unsigned int)&vsnprintf,
            16,
            (unsigned int)"%d",
            v22,
            v6,
            v19);
          v38[0] = v39;
          std::string::_M_construct<char const*>(v38, a2, v7);
          LODWORD(v8) = -641595235;
        }
        else if ( (_DWORD)v8 == -1270187572 )
        {
          dword_7DB82C8 = 0;
          LODWORD(v8) = -2138602275;
        }
      }
      if ( (_DWORD)v8 != -641595235 )
        break;
      v8 = &loc_560A5DD;
    }
  }
  while ( (_DWORD)v8 != (_DWORD)&loc_560A5DD );
  sub_56C46C0(needle, a1, v40, v38);
  sub_56C3008(&v32, a1, v38);
  sub_56B4244(&v29);
  v13 = v36;
  memcpy(a5 + 512, *(const void **)needle, v36);
  a5[767] = v13;
  v14 = v29;
  v15 = v30;
  memcpy(a5, v29, v30);
  a5[255] = v15;
  v16 = v32;
  v17 = v33;
  memcpy(a5 + 256, v32, v33);
  a5[511] = v17;
  if ( v14 != &v31 )
  {
    operator delete(v14);
    v16 = v32;
  }
  if ( v16 != &v34 )
    operator delete(v16);
  if ( *(_BYTE **)needle != v37 )
    operator delete(*(void **)needle);
  if ( v38[0] != v39 )
    operator delete(v38[0]);
  if ( v40[0] != &v41 )
    operator delete(v40[0]);
  return 0;
}


// ===== op60_helper @ 0x5ce6006 =====
unsigned __int64 __fastcall sub_5CE6006(__int64 a1, __int64 a2, __int64 *a3)
{
  int i; // eax
  _QWORD *v6; // [rsp+8h] [rbp-50h]
  __int64 v7; // [rsp+18h] [rbp-40h]
  __int64 v8; // [rsp+20h] [rbp-38h]
  _QWORD v9[6]; // [rsp+28h] [rbp-30h] BYREF

  v9[1] = __readfsqword(0x28u);
  v9[0] = a2;
  for ( i = 798745500; ; i = -1582962914 )
  {
    while ( i > -516094581 )
    {
      if ( i == -516094580 )
      {
        *a3 = (__int64)(v6[1] - *v6) >> 3;
        std::vector<long>::emplace_back<long &>(v6, v9);
        i = -1582962914;
      }
      else if ( i == 1177461696 )
      {
        v8 = sub_5CE6230(v7, v6[1], v9);
        i = -2063907392;
        if ( v8 == v6[1] )
          i = -516094580;
      }
      else
      {
        v6 = (_QWORD *)(a1 + 32);
        v7 = *(_QWORD *)(a1 + 32);
        i = 1177461696;
      }
    }
    if ( i != -2063907392 )
      break;
    *a3 = (v8 - *v6) >> 3;
  }
  return __readfsqword(0x28u);
}
