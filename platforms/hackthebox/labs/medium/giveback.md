---
hidden: true
---

# Giveback

This is my first active machine solving on HTB<br>

## Reconnaissance

lets start with rustscan&#x20;

```
rustscan -a 10.10.11.94 -b 500 -t 500 -- -A -sC -sV 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 2147483484'.
Open 10.10.11.94:22
Open 10.10.11.94:80
Open 10.10.11.94:30686
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sC -sV" on ip 10.10.11.94
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-02 09:52 UTC

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 66:f8:9c:58:f4:b8:59:bd:cd:ec:92:24:c3:97:8e:9e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCNmct03SP9FFs6NQ+Pih2m65SYS/Kte9aGv3C8l43TJGj2UcSrcheEX2jBL/jbje/HRafbJcGqz1bKeQo1cbAc=
|   256 96:31:8a:82:1a:65:9f:0a:a2:6c:ff:4d:44:7c:d3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjor5/gXrTqGEWiETEzhgoni1P2kXV3B4O2/v2SGnH0

80/tcp    open  http    syn-ack nginx 1.28.0
|_http-favicon: Unknown favicon MD5: 000BF649CC8F6BF27CFB04D1BCDCD3C7
|_http-generator: WordPress 6.8.1
|_http-title: GIVING BACK IS WHAT MATTERS MOST &#8211; OBVI
|_http-server-header: nginx/1.28.0
| http-methods: 
|_  Supported Methods: GET HEAD POST
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/

30686/tcp open  http    syn-ack Golang net/http server
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Load-Balancing-Endpoint-Weight: 1
|     Date: Sun, 02 Nov 2025 09:52:52 GMT
|     Content-Length: 127
|     "service": {
|     "namespace": "default",
|     "name": "wp-nginx-service"
|     "localEndpoints": 1,
|     "serviceProxyHealthy": true
|   GenericLines, Help, LPDString, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Load-Balancing-Endpoint-Weight: 1
|     Date: Sun, 02 Nov 2025 09:52:32 GMT
|     Content-Length: 127
|     "service": {
|     "namespace": "default",
|     "name": "wp-nginx-service"
|     "localEndpoints": 1,
|     "serviceProxyHealthy": true
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Load-Balancing-Endpoint-Weight: 1
|     Date: Sun, 02 Nov 2025 09:52:33 GMT
|     Content-Length: 127
|     "service": {
|     "namespace": "default",
|     "name": "wp-nginx-service"
|     "localEndpoints": 1,
|_    "serviceProxyHealthy": true
|_http-title: Site doesn't have a title (application/json).
|_http-favicon: Unknown favicon MD5: 078C07D5669A42740EF813D5300EBA4D
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS

```

Hmm a wordpress site ..

lets use wpscan&#x20;

```
wpscan --url http://10.10.11.94 -P /usr/share/wordlists/rockyou.txt  
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
 
[+] URL: http://10.10.11.94/ [10.10.11.94]
[+] Started: Sun Nov  2 16:09:02 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.28.0
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] WordPress version 6.8.1 identified (Outdated, released on 2025-04-30).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.11.94/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=6.8.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.11.94/, Match: 'WordPress 6.8.1'

[+] WordPress theme in use: bizberg
 | Location: http://10.10.11.94/wp-content/themes/bizberg/
 | Latest Version: 4.2.9.79 (up to date)
 | Last Updated: 2024-06-09T00:00:00.000Z
 | Style URL: http://10.10.11.94/wp-content/themes/bizberg/style.css?ver=6.8.1
 | Style Name: Bizberg
 | Style URI: https://bizbergthemes.com/downloads/bizberg-lite/
 | Description: Bizberg is a perfect theme for your business, corporate, restaurant, ingo, ngo, environment, nature,...
 | Author: Bizberg Themes
 | Author URI: https://bizbergthemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 4.2.9.79 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.11.94/wp-content/themes/bizberg/style.css?ver=6.8.1, Match: 'Version: 4.2.9.79'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] *
 | Location: http://10.10.11.94/wp-content/plugins/*/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | The version could not be determined.

[+] give
 | Location: http://10.10.11.94/wp-content/plugins/give/
 | Last Updated: 2025-08-20T14:13:00.000Z
 | [!] The version is out of date, the latest version is 4.7.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By:
 |  Urls In 404 Page (Passive Detection)
 |  Meta Tag (Passive Detection)
 |  Javascript Var (Passive Detection)
 |
 | Version: 3.14.0 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://10.10.11.94/wp-content/plugins/give/assets/dist/css/give.css?ver=3.14.0
 | Confirmed By:
 |  Meta Tag (Passive Detection)
 |   - http://10.10.11.94/, Match: 'Give v3.14.0'
 |  Javascript Var (Passive Detection)
 |   - http://10.10.11.94/, Match: '"1","give_version":"3.14.0","magnific_options"'

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:02:58 <=====================================================================================================================> (137 / 137) 100.00% Time: 00:02:58

[i] No Config Backups Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:42 <======================================================================================================================> (10 / 10) 100.00% Time: 00:00:42

[i] User(s) Identified:

[+] user
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.11.94/wp-json/wp/v2/users/?per_page=100&page=1
 |  Oembed API - Author URL (Aggressive Detection)
 |   - http://10.10.11.94/wp-json/oembed/1.0/embed?url=http://10.10.11.94/&format=json
 |  Author Sitemap (Aggressive Detection)
 |   - http://10.10.11.94/wp-sitemap-users-1.xml
 |  Login Error Messages (Aggressive Detection)

[+] Performing password attack on Wp Login against 1 user/s
[SUCCESS] - user / password                                                                                                                                                                         
Trying user / iloveyou Time: 00:00:27 <                                                                                                                       > (5 / 14344397)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: user, Password: password

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Nov  2 16:17:30 2025
[+] Requests Done: 204
[+] Cached Requests: 8
[+] Data Sent: 52.214 KB
[+] Data Received: 384.007 KB
[+] Memory used: 277.711 MB
[+] Elapsed time: 00:08:27

```

Vulnerable plugin name "give" ( matches the name of machine )

found this :&#x20;

{% embed url="https://github.com/EQSTLab/CVE-2024-5932" %}

also lets login in with the found creds&#x20;

we need a donation form path to get rce&#x20;

