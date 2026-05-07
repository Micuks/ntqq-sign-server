// ===== sub_5CCC307_vm_dispatcher @ 0x5ccc307 (size 0x299) =====
__int64 __fastcall sub_5CCC307(int a1, const void *a2, __int64 a3, const void *a4, __int64 a5, int a6)
{
  __int64 v6; // r13
  _WORD *v7; // r15
  size_t v8; // rbp
  unsigned __int64 v9; // rax
  int v10; // r14d
  bool v11; // cf
  size_t v12; // rax
  size_t v13; // r12
  int v14; // eax
  char *v15; // rbx
  char v17; // [rsp+0h] [rbp-A8h]
  bool v18; // [rsp+Fh] [rbp-99h]
  __int64 size; // [rsp+18h] [rbp-90h]
  __int64 v20; // [rsp+20h] [rbp-88h]
  unsigned int v21; // [rsp+38h] [rbp-70h]
  int v23; // [rsp+48h] [rbp-60h]
  void *v24; // [rsp+50h] [rbp-58h]
  _QWORD *v25; // [rsp+58h] [rbp-50h]
  void **v26; // [rsp+60h] [rbp-48h]
  unsigned int *ptr; // [rsp+68h] [rbp-40h]

  v18 = a3 == 0;
  v8 = (unsigned int)a5;
  v20 = (unsigned int)a5 + 1LL;
  v9 = (unsigned int)(a5 + 1);
  v23 = a5;
  v10 = -84233460;
  if ( !a5 )
    v10 = -573241303;
  if ( !a4 )
    v10 = -573241303;
  v21 = a3;
  size = (unsigned int)a3 + 1LL;
  v11 = v9 < (unsigned int)a5;
  v12 = v9 - (unsigned int)a5;
  v13 = 0;
  if ( !v11 )
    v13 = v12;
  v14 = 415459157;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( v14 <= -84233461 )
      {
        if ( v14 > -896693793 )
        {
          if ( v14 == -896693792 )
          {
            v14 = 1894210106;
            v6 = 0;
          }
          else
          {
            v6 = sub_5CCBC83(a1, (unsigned int)"LLL", (_DWORD)ptr, (_DWORD)v7, a5, a6, v17);
            ptr = 0;
            v14 = 1894210106;
          }
        }
        else if ( v14 == -1808749353 )
        {
          *v25 = v24;
          memset(*((void **)ptr + 1), 0, *ptr + 1);
          v26 = (void **)ptr;
          v14 = 197285552;
        }
        else
        {
          ptr = (unsigned int *)malloc(0x10u);
          *ptr = v21;
          *((_WORD *)ptr + 2) = 30;
          v24 = malloc(size);
          v25 = ptr + 2;
          v14 = -1808749353;
        }
      }
      if ( v14 > 415459156 )
        break;
      if ( v14 == -84233460 )
      {
        v7 = malloc(0x10u);
        *(_DWORD *)v7 = v23;
        v7[2] = 30;
        v15 = (char *)malloc(v20);
        *((_QWORD *)v7 + 1) = v15;
        memset(&v15[v8], 0, v13);
        memcpy(v15, a4, v8);
        v14 = -573241303;
      }
      else
      {
        memcpy(v26[1], a2, *ptr);
        LODWORD(v7) = 0;
        v14 = v10;
      }
    }
    if ( v14 != 415459157 )
      break;
    v14 = -1239915430;
    if ( v18 )
      v14 = -896693792;
    if ( !a2 )
      v14 = -896693792;
  }
  return v6;
}


// callees of sub_5CCC307_vm_dispatcher:
//    0x5ccbc83 (size 0x122)
//    0x7ae5bd0 (size 0x6)
//    0x7ae5c80 (size 0x6)
//    0x7ae6320 (size 0x6)
//    0x7ae63b0 (size 0x6)
//    0x7ae6aa0 (size 0x6)

// ===== sub_5CCD94A_op60_outer @ 0x5ccd94a (size 0x174) =====
unsigned __int64 __fastcall sub_5CCD94A(__int64 a1, __int64 a2, __int64 a3, int a4, __int64 a5)
{
  unsigned __int64 v6; // rax
  void *v7; // rbp
  int v8; // r14d
  int v9; // ecx
  int v10; // eax
  __int64 v13; // [rsp+18h] [rbp-50h]
  __int64 v14; // [rsp+20h] [rbp-48h]
  __int64 v15[8]; // [rsp+28h] [rbp-40h] BYREF

  v6 = __readfsqword(0x28u);
  v7 = &unk_1BDF51D;
  if ( !a3 )
    LODWORD(v7) = -969876049;
  v15[1] = v6;
  v8 = 1103062146;
  if ( a4 )
    v8 = 47587628;
  v9 = -1350401156;
  do
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          v10 = v9;
          if ( v9 > 47587627 )
            break;
          if ( v9 > -969876050 )
          {
            if ( v9 == -969876049 )
            {
              *(_QWORD *)(*(_QWORD *)(a1 + 16) + 8 * a2) = 0;
              v9 = 1344273253;
            }
            else if ( v9 == (_DWORD)&unk_1BDF51D )
            {
              *(_BYTE *)(*(_QWORD *)(a1 + 24) + a2) = 1;
              v15[0] = 0;
              sub_5CE6006(a1, a3, v15);
              v9 = 1932422337;
            }
          }
          else
          {
            v9 = v8;
            if ( v10 != -1350401156 )
            {
              v9 = v10;
              if ( v10 == -1116658871 )
              {
                *(_QWORD *)(v14 + 8 * a2) = v13;
                v9 = 1344273253;
              }
            }
          }
        }
        if ( v9 > 1344273252 )
          break;
        if ( v9 == 47587628 )
        {
          sub_5CE5A3E(a1, a5);
          v9 = 1103062146;
        }
        else if ( v9 == 1103062146 )
        {
          v9 = (int)v7;
        }
      }
      if ( v9 != 1932422337 )
        break;
      v13 = v15[0];
      v14 = *(_QWORD *)(a1 + 16);
      v9 = -1116658871;
    }
  }
  while ( v9 != 1344273253 );
  return __readfsqword(0x28u);
}


// callees of sub_5CCD94A_op60_outer:
//    0x5ce5a3e (size 0x5c8)
//    0x5ce6006 (size 0x123)
//    0x7ae6aa0 (size 0x6)