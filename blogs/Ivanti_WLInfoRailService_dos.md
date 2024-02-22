## Ivanti Avalanche WLInfoRailService 未授权堆溢出漏洞

### 漏洞描述

Ivanti Avalanche(6.4.2.313) WLInfoRailService服务中存在一个整数溢出漏洞，未授权的远程攻击者可以在受影响的Ivanti Avalanche系统中造成堆溢出漏洞。<br>

版本信息:<br>

Ivanti Avalanche	:  6.4.2.313<br>

文件名: Ivanti-Avalanche_windows-x64_6_4_2_313.exe<br>

下载链接 : https://download.wavelink.com/Files/Ivanti-Avalanche_windows-x64_6_4_2_313.exe<br>

### 漏洞细节

漏洞存在于C:\Program Files\Wavelink\Avalanche\Inforail\WLInfoRailService.exe 文件中.<br>

```
signed int __thiscall sub_40F880(char *this, message_header_struct *message_header_struct, unsigned int header_buf_size_v2)
{
  signed int size_v3_; // eax
  u_long size_v1_; // edi
  unsigned int v7; // edx
  int *v8; // ebx
  int *v9; // esi
  char *v10; // ebx
  void *v11; // eax
  u_long can_be_0xffffffff; // [esp+1Ch] [ebp+4h]

  if ( header_buf_size_v2 < 0xC )
    return 0;
  size_v1_ = ntohl(message_header_struct->size_v1);
  can_be_0xffffffff = ntohl(message_header_struct->size_v2);// The value of size_v2 was not checked !!!
  size_v3_ = ntohl(message_header_struct->size_v3);
  *this = size_v3_;
  if ( size_v3_ )
  {
    v7 = can_be_0xffffffff + size_v1_ + 12;     // Integer overflow !!!
    if ( v7 > header_buf_size_v2 )
      return -1;
    if ( size_v1_ > 0x17 )
      return -2;
    if ( size_v3_ > 0xD )
      return -3;
    v8 = &message_header_struct->value_0xc;
    qmemcpy(this + 4, v8, 4 * (size_v1_ >> 2));
    v9 = &v8[size_v1_ >> 2];
    v10 = v8 + size_v1_;
    qmemcpy(&this[4 * (size_v1_ >> 2) + 4], v9, size_v1_ & 3);
    this[size_v1_ + 4] = 0;
    if ( !can_be_0xffffffff )
    {
      **(this + 39) = 0;
      return size_v1_ + 12;
    }
    if ( can_be_0xffffffff >= 0x80 )
    {
      v11 = operator new(can_be_0xffffffff + 1);
      *(this + 39) = v11;
      if ( !v11 )
        return -4;
      v7 = can_be_0xffffffff + size_v1_ + 12;
    }
    qmemcpy(*(this + 39), v10, can_be_0xffffffff);// heap buffer overflow !!!
    *(can_be_0xffffffff + *(this + 39)) = 0;
    size_v3_ = v7;
  }
  return size_v3_;
}
```

message_header_struct结构体的数据攻击者完全可控。<br>

message_header_struct->size_v2没有做校验，在进行加法运算时可以造成整数溢出。<br>

之后会利用 message_header_struct->size_v2 的值进行堆块分配，并进行数据拷贝，造成堆溢出漏洞。<br>

### 漏洞利用

目前的影响是拒绝服务。<br>