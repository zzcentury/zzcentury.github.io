## NETGEAR R7000P Httpd quick_qos_edit_serv.cgi 栈溢出远程代码执行漏洞

### Vulnerability description

This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of NETGEAR R7000P routers. Authentication is required to exploit this vulnerability.<br>
<br>
A stack overflow vulnerability exists in NETGEAR R7000P V1.3.3.154_10.1.86, which can be exploited by an authenticated remote attacker to obtain a root shell on an affected NETGEAR R7000P.<br>

### Vulnerability details

The vulnerability is in the /usr/sbin/httpd file, specifically in the function that handles quick_qos_add_edit.cgi :<br>
<br>

```
int __fastcall quick_qos_edit_serv_cgi(int a1, int a2)
{
  ******
  GetRequetParam(a1, "apply", &v39, 2048);
  if ( !v39 )
    return sub_1C8D4("QOS_down_streaming.htm", a2);
  v4 = acosNvramConfig_get("quick_qos_priority_edit");
  v5 = atoi(v4);
  if ( !acosNvramConfig_match("quick_qos_rule", "0") )
  {
	******
  }
  GetRequetParam(a1, "service_type", &v39, 0x800);
  if ( !strcmp(&v39, "new") )
  {
    quick_qos_rule_edit_value__ = acosNvramConfig_get("quick_qos_rule_edit");
    maybe_quick_qos_add_service_vul_strncpy1("quick_qos_add_service", quick_qos_rule_edit_value__);// sinto here
    ******
  }
  ******
}
```

The quick_qos_edit_serv_cgi function calls maybe_quick_qos_add_service_vul_strncpy1 to handle the Nvram parameter quick_qos_add_service.<br>
<br>
There are several stack overflows in the maybe_quick_qos_add_service_vul_strncpy1 function.<br>

```
int __fastcall maybe_quick_qos_add_service_vul_strncpy1(int quick_qos_add_service, const char *quick_qos_rule_edit_value)
{
  const char *v4; // r0
  char *quick_qos_add_service_tmp; // r0
  char *v6; // r8
  char *quick_qos_add_service_tmp_tmp; // r1
  int v8; // r0
  int *v9; // r1
  char *v10; // r6
  int stack_buffer; // [sp+0h] [bp-5E0h] BYREF
  char v13[1496]; // [sp+4h] [bp-5DCh] BYREF
  int quick_qos_add_service_value; // [sp+5DCh] [bp-4h] BYREF
  _BYTE v15[1496]; // [sp+5E0h] [bp+0h] BYREF

  quick_qos_add_service_value = 0;
  memset(v15, 0, sizeof(v15));
  stack_buffer = 0;
  memset(v13, 0, sizeof(v13));
  v4 = acosNvramConfig_get(quick_qos_add_service);
  strcpy(&quick_qos_add_service_value, v4);
  quick_qos_add_service_tmp = strstr(&quick_qos_add_service_value, quick_qos_rule_edit_value);
  v6 = quick_qos_add_service_tmp;
  if ( quick_qos_add_service_tmp )
  {
    if ( quick_qos_add_service_tmp == &quick_qos_add_service_value )
    {
      quick_qos_add_service_tmp_tmp = strchr(quick_qos_add_service_tmp, '@');
      if ( !quick_qos_add_service_tmp_tmp )
      {
        v8 = quick_qos_add_service;
        v9 = &byte_11AE6F;
LABEL_10:
        acosNvramConfig_set(v8, v9);
        return 0;
      }
      strcpy(&stack_buffer, quick_qos_add_service_tmp_tmp + 1);// stack overflow 1
    }
    else
    {
      v10 = strchr(quick_qos_add_service_tmp, '@');
      if ( v10 )
      {
        strncpy(&stack_buffer, &quick_qos_add_service_value, v6 - &quick_qos_add_service_value);// stack overflow 2
        strcat(&stack_buffer, v10 + 1);         // stack overflow 3
      }
      else
      {
        strncpy(&stack_buffer, &quick_qos_add_service_value, &v6[~&quick_qos_add_service_value]);// stack overflow 4
      }
    }
    v8 = quick_qos_add_service;
    v9 = &stack_buffer;
    goto LABEL_10;
  }
  return 0;
}
```

The maybe_quick_qos_add_service_vul_strncpy1 function processes the Nvram parameter quick_qos_add_service and copies the processed value to the stack variable stack_buffer.<br>
<br>
The stack_buffer distance function returns the address 0x5E0.<br>
<br>
The maximum length of the quick_qos_add_service parameter is 0x800.<br>
<br>
You can control the length and value of the Nvram parameter quick_qos_add_service by repeatedly calling the quick_qos_add_serv_cgi function.<br>

```
int __fastcall quick_qos_add_serv_cgi(int a1, int a2)
{
	******
    GetRequetParam(a1, "qos_protocol", &qos_protocol, 0x800);
    if ( qos_protocol )
      strlcat(&quick_qos_add_service_value_more, &qos_protocol, 0x400u);
	******
    strlcat(&quick_qos_add_service_value_more, "&", 0x400u);
    strlcat(&quick_qos_add_service_value_more, qos_port_start_, 0x400u);
    strlcat(&quick_qos_add_service_value_more, "&", 0x400u);
    strlcat(&quick_qos_add_service_value_more, qos_port_end_, 0x400u);
    GetRequetParam(a1, "qos_priorityList", &qos_protocol, 0x800);// more read
    qos_priorityList = atoi(&qos_protocol);
    if ( qos_priorityList )
    {
      switch ( qos_priorityList )
      {
        case 1:
          qos_priorityList_type = "quick_qos_service_high";
          break;
        case 2:
          qos_priorityList_type = "quick_qos_service_normal";
          break;
        case 3:
          qos_priorityList_type = "quick_qos_service_low";
          break;
        default:
LABEL_27:
          v17 = acosNvramConfig_get("quick_qos_add_service");
          strlcpy(quick_qos_add_service_value, v17, 0x800);
          if ( *acosNvramConfig_get("quick_qos_add_service") )
            strlcat(quick_qos_add_service_value, "@", 0x800u);
          strlcat(quick_qos_add_service_value, &quick_qos_add_service_value_more, 0x800u);
          acosNvramConfig_set("quick_qos_add_service", quick_qos_add_service_value);// first : into here 
          acosNvramConfig_set("qos_enable", "1");
          return sub_1C8D4("QOS_down_streaming.htm", a2);
      }
    }
    ******
}
```

Specifically, the qos_protocol parameter is used to control the length and value of the Nvram parameter quick_qos_add_service.<br>

### Vulnerability exploitation

The exploit is to override the return address and use ROP to call the system function.<br>
<br>
I get the root shell of the device by executing `/bin/utelnetd -p3363 -l /bin/sh -d;`.<br>