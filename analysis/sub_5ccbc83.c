__int64 sub_5CCBC83(__int64 a1, __int64 a2, ...)
{
  void *v2; // rbx
  __int64 v3; // rbx
  gcc_va_list va; // [rsp+B0h] [rbp-A8h] BYREF
  _BYTE v6[64]; // [rsp+C8h] [rbp-90h] BYREF
  _BYTE v7[32]; // [rsp+108h] [rbp-50h] BYREF
  unsigned __int64 v8; // [rsp+128h] [rbp-30h]

  va_start(va, a2);
  v8 = __readfsqword(0x28u);
  v2 = malloc(0x17Au);
  memcpy(v2, &unk_DA82C0, 0x17Au);
  sub_5CCD0B4(v6, v2);
  std::string::_M_assign(v7, a1);
  sub_5CCD14A(v6, a2, va);
  v3 = sub_5CCF0B0(v6);
  sub_5CCBAE4(v6);
  return v3;
}
